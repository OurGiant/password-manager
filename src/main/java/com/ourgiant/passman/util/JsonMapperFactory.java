package com.ourgiant.passman.util;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Shared Jackson setup for reading GitHub's releases API response: tolerant of unknown fields. */
public final class JsonMapperFactory {

    private JsonMapperFactory() {
    }

    public static ObjectMapper createMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }
}
