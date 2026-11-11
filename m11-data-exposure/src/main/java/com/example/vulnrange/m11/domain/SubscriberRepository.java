package com.example.vulnrange.m11.domain;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/** Repository for the exposure demos. */
@Repository
public interface SubscriberRepository extends CrudRepository<SubscriberEntity, String> {

    List<SubscriberEntity> findByEmail(String email);

    Page<SubscriberEntity> findAll(Pageable pageable);
}
