package com.acme.orders;

import com.google.common.collect.ImmutableList;
import java.util.List;

/** Guava is used here, but none of its vulnerable methods are. */
public class Catalog {

    public static List<String> defaultItems() {
        return ImmutableList.of("book", "pen", "notebook");
    }
}
