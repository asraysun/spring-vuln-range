package com.example.vulnrange.m06.safe;

import java.io.ObjectInputFilter;

public interface FilteringObjectInputStream {
    ObjectInputFilter checkInput(ObjectInputFilter.FilterInfo filterInfo);
}
