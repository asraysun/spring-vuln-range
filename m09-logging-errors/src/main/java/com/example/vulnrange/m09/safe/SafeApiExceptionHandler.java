package com.example.vulnrange.m09.safe;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Scoped to {@code /safe9} on purpose: a global {@code @RestControllerAdvice} would also "fix" the
 * vulnerable endpoints and the demonstration would disappear. In a real service this class is global.
 *
 * <p>Rules encoded here:
 * <ul>
 *   <li>clients get a stable, generic problem document plus a correlation id — never a stack trace,
 *       SQL fragment, file path, internal host or library version;</li>
 *   <li>the full exception goes to the log (with the correlation id) and to the APM, not to the
 *       response;</li>
 *   <li>validation feedback describes the violated rule, not the stored state of an account;</li>
 *   <li>every security-relevant outcome is logged as an event with a masked subject.</li>
 * </ul>
 */
@RestControllerAdvice(basePackages = "com.example.vulnrange.m09.safe")
public class SafeApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(SafeApiExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail invalid(MethodArgumentNotValidException e, HttpServletRequest request) {
        List<Map<String, String>> violations = e.getBindingResult().getFieldErrors().stream()
                .map(SafeApiExceptionHandler::describe)
                .toList();
        log.info("request rejected path={} violations={}", request.getRequestURI(), violations.size());
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "request did not pass validation");
        detail.setProperty("correlationId", correlationId());
        detail.setProperty("violations", violations);
        return detail;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail badRequest(IllegalArgumentException e, HttpServletRequest request) {
        // The developer message is logged, not returned.
        log.warn("bad request path={} reason={}", request.getRequestURI(),
                CorrelationIdFilter.sanitiseForLog(e.getMessage(), 200));
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "invalid request");
        detail.setProperty("correlationId", correlationId());
        return detail;
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> unexpected(Exception e, HttpServletRequest request) {
        String incidentId = UUID.randomUUID().toString();
        // Full detail for the responders; nothing identifying for the caller.
        log.error("unhandled failure incidentId={} path={} cid={}", incidentId, request.getRequestURI(),
                correlationId(), e);
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR, "the request could not be completed");
        detail.setProperty("correlationId", correlationId());
        // An incident id is safe to share: it is a lookup key into your own log store.
        detail.setProperty("incidentId", incidentId);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(detail);
    }

    private static Map<String, String> describe(FieldError error) {
        return Map.of(
                "field", error.getField(),
                "rule", String.valueOf(error.getDefaultMessage()));
    }

    private static String correlationId() {
        String cid = MDC.get(CorrelationIdFilter.MDC_KEY);
        return cid == null ? "n/a" : cid;
    }
}
