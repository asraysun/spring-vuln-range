package com.example.vulnrange.m06.vuln;

import java.io.Serial;
import java.io.Serializable;

/**
 * VULNERABLE (intentional): a class whose constructor, setter and {@code hashCode} all perform
 * observable work.
 *
 * <p>When an untrusted stream is deserialized, the attacker chooses <em>which</em> classes get
 * instantiated and which of their methods the runtime calls ({@code readObject}, {@code hashCode},
 * {@code equals}, {@code compareTo}, JMX getters...). Observing {@link #hashCode()} run from a
 * {@code HashMap} key inside submitted bytes proves the primitive. Chaining it into an exploit is a
 * separate step and is deliberately not provided in this range.
 */
public class Probe implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String note;

    public Probe() {
        SideEffects.record("Probe.<init> ran while deserializing client bytes");
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
        SideEffects.record("Probe.setNote('" + note + "') ran from untrusted payload");
    }

    @Override
    public int hashCode() {
        SideEffects.record("Probe.hashCode() ran from untrusted payload (HashMap key)");
        return note == null ? 7 : note.hashCode();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Probe p && java.util.Objects.equals(p.note, this.note);
    }
}
