package com.acme.orders;

import java.util.Map;

/**
 * Entry point of the orders service.
 *
 * Note: the h2 database driver is only kept for local integration testing;
 * production code never opens an h2 connection.
 */
public class OrdersApp {

    public static void main(String[] args) {
        String path = args.length > 0 ? args[0] : "/orders/42";
        Router router = new Router();
        System.out.println(router.route(path));

        NotificationFormatter formatter = new NotificationFormatter();
        System.out.println(formatter.format("Order ${orderId} has shipped", Map.of("orderId", "42")));

        ConfigImporter importer = new ConfigImporter();
        System.out.println(importer.importConfig("limits: {maxItems: 10}"));

        System.out.println(Catalog.defaultItems());
    }
}
