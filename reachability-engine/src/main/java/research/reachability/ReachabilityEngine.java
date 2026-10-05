package research.reachability;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import sootup.callgraph.CallGraph;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootMethod;
import sootup.core.model.SourceType;
import sootup.core.signatures.MethodSignature;
import sootup.java.bytecode.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.inputlocation.JrtFileSystemAnalysisInputLocation;
import sootup.java.core.JavaSootClass;
import sootup.java.core.views.JavaView;

/**
 * Reachability engine for the triage study.
 *
 * Builds a Class Hierarchy Analysis (CHA) call graph with SootUp from the target
 * project's main methods, then decides, for every advisory in alerts.json, whether
 * the curated vulnerable methods are called from reachable application code.
 *
 * Status per advisory (same contract the agent and the slot check read):
 *   confirmed  a reachable application method calls a vulnerable method (call path given)
 *   absent     no reachable call to a vulnerable method (or the dependency is not used at all)
 *   ambiguous  cannot be decided statically: no vulnerable-method data for a used dependency,
 *              or the only calls are in code reachable through reflection
 *   error      the analysis could not run for this dependency (e.g. jar not found)
 */
public final class ReachabilityEngine {

    private static final String ENGINE_VERSION = "sootup 1.3.0";
    private static final Set<String> REFLECTION = Set.of(
            "java.lang.Class#forName", "java.lang.Class#newInstance", "java.lang.Class#getMethod",
            "java.lang.Class#getDeclaredMethod", "java.lang.reflect.Method#invoke",
            "java.lang.reflect.Constructor#newInstance");

    /** One call site found in an application method body. */
    record Call(MethodSignature caller, String calleeClass, String calleeMethod, String callee) {}

    private ReachabilityEngine() {}

    public static void main(String[] args) throws Exception {
        Map<String, String> a = parseArgs(args);
        if (a.containsKey("help") || !a.keySet().containsAll(List.of("alerts", "classes", "deps", "methods", "out"))) {
            System.out.println("usage: --alerts alerts.json --classes target/classes --deps target/dependency "
                    + "--methods vulnerable_methods.json --out reachability.json [--project name]");
            System.exit(a.containsKey("help") ? 0 : 2);
        }
        ObjectMapper json = new ObjectMapper();
        JsonNode alerts = json.readTree(new File(a.get("alerts")));
        JsonNode methods = json.readTree(new File(a.get("methods"))).path("entries");
        Path classesDir = Path.of(a.get("classes"));
        Path depsDir = Path.of(a.get("deps"));

        // ---- 1. application classes and dependency jars
        Set<String> appClasses = listClassNames(classesDir);
        List<Path> jars = listJars(depsDir);
        System.err.printf("[engine] %d application classes, %d dependency jars%n", appClasses.size(), jars.size());

        List<AnalysisInputLocation> inputs = new ArrayList<>();
        inputs.add(new JavaClassPathAnalysisInputLocation(classesDir.toString(), SourceType.Application));
        if (!jars.isEmpty()) {
            String cp = jars.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator));
            inputs.add(new JavaClassPathAnalysisInputLocation(cp, SourceType.Library));
        }
        inputs.add(new JrtFileSystemAnalysisInputLocation());
        JavaView view = new JavaView(inputs);

        List<JavaSootClass> classes = new ArrayList<>();
        for (String name : appClasses) {
            view.getClass(view.getIdentifierFactory().getClassType(name)).ifPresent(classes::add);
        }

        // ---- 2. entry points: every main method (fallback: every public concrete method)
        List<MethodSignature> entries = new ArrayList<>();
        for (JavaSootClass c : classes) {
            for (SootMethod m : c.getMethods()) {
                MethodSignature s = m.getSignature();
                if (m.isStatic() && s.getName().equals("main") && s.getParameterTypes().size() == 1
                        && s.getParameterTypes().get(0).toString().endsWith("String[]")) {
                    entries.add(s);
                }
            }
        }
        if (entries.isEmpty()) {
            for (JavaSootClass c : classes) {
                for (SootMethod m : c.getMethods()) {
                    if (m.isPublic() && !m.isAbstract()) {
                        entries.add(m.getSignature());
                    }
                }
            }
        }
        System.err.printf("[engine] %d entry point(s)%n", entries.size());

        // ---- 3. call graph (CHA) from the entry points
        CallGraph cg = new ClassHierarchyAnalysisAlgorithm(view).initialize(entries);
        Set<MethodSignature> reachable = cg.getMethodSignatures().stream()
                .filter(s -> appClasses.contains(s.getDeclClassType().getFullyQualifiedName()))
                .collect(Collectors.toSet());
        reachable.addAll(entries);
        System.err.printf("[engine] %d reachable application methods%n", reachable.size());

        // ---- 4. every call site in application code (reachable or not)
        List<Call> reachableCalls = new ArrayList<>();
        List<Call> unreachableCalls = new ArrayList<>();
        for (JavaSootClass c : classes) {
            for (SootMethod m : c.getMethods()) {
                if (!m.hasBody()) {
                    continue;
                }
                MethodSignature caller = m.getSignature();
                for (Stmt st : m.getBody().getStmts()) {
                    if (!st.containsInvokeExpr()) {
                        continue;
                    }
                    MethodSignature t = st.getInvokeExpr().getMethodSignature();
                    Call call = new Call(caller, t.getDeclClassType().getFullyQualifiedName(), t.getName(), t.toString());
                    (reachable.contains(caller) ? reachableCalls : unreachableCalls).add(call);
                }
            }
        }
        boolean reflection = reachableCalls.stream().anyMatch(c -> REFLECTION.contains(c.calleeClass() + "#" + c.calleeMethod()));

        // ---- 5. decide every advisory
        ArrayNode results = json.createArrayNode();
        for (JsonNode alert : alerts) {
            JsonNode dep = alert.path("dependency");
            String artifact = dep.path("artifact_id").asText();
            String version = dep.path("version").asText();
            Optional<Path> jar = jars.stream()
                    .filter(p -> p.getFileName().toString().startsWith(artifact + "-" + version)).findFirst();
            Set<String> depClasses = jar.isPresent() ? jarClassNames(jar.get()) : Set.of();

            for (JsonNode vuln : alert.path("vulnerabilities")) {
                ObjectNode r = results.addObject();
                r.set("dependency", dep.deepCopy());
                r.put("vulnerability_id", vuln.path("id").asText());
                List<String[]> targets = targetsFor(methods, artifact, vuln);
                ArrayNode tnode = r.putArray("targets");
                for (String[] t : targets) {
                    tnode.addObject().put("class", t[0]).put("method", t[1]);
                }
                r.put("method_source", targets.isEmpty() ? "none" : "curated");
                ArrayNode evidence = r.putArray("evidence");
                r.putNull("ambiguity_cause");
                r.putNull("error");

                if (jar.isEmpty()) {
                    set(r, "error", "Dependency jar not found in " + depsDir);
                    r.putObject("error").put("code", "jar_not_found").put("message", artifact + "-" + version);
                    continue;
                }
                List<Call> hits = matching(reachableCalls, targets);
                List<Call> hiddenHits = matching(unreachableCalls, targets);
                boolean usedReachable = reachableCalls.stream().anyMatch(c -> depClasses.contains(c.calleeClass()));
                boolean usedUnreachable = unreachableCalls.stream().anyMatch(c -> depClasses.contains(c.calleeClass()));

                if (!hits.isEmpty()) {
                    set(r, "confirmed", "A reachable application method calls a vulnerable method.");
                    for (Call h : hits) {
                        ObjectNode e = evidence.addObject();
                        e.put("type", "call_path");
                        ArrayNode path = e.putArray("path");
                        pathTo(cg, entries, h.caller()).forEach(s -> path.add(s.toString()));
                        path.add(h.callee());
                        e.put("length", path.size());
                    }
                } else if (!targets.isEmpty() && !hiddenHits.isEmpty() && reflection) {
                    set(r, "ambiguous", "The vulnerable method is called only from code that is reached through reflection.");
                    r.put("ambiguity_cause", "reflection");
                } else if (!targets.isEmpty()) {
                    set(r, "absent", usedReachable
                            ? "The dependency is used, but no reachable code calls its vulnerable methods."
                            : "The dependency is not used by reachable application code.");
                } else if (!usedReachable && !usedUnreachable) {
                    set(r, "absent", "The dependency is not used by application code.");
                } else if (!usedReachable && reflection) {
                    set(r, "ambiguous", "The dependency is used only from code reached through reflection.");
                    r.put("ambiguity_cause", "reflection");
                } else if (!usedReachable) {
                    set(r, "absent", "The dependency is used only from code that is never called.");
                } else {
                    set(r, "ambiguous", "The dependency is used, but no vulnerable-method data exists for this advisory.");
                    r.put("ambiguity_cause", "no_method_data");
                }
            }
        }

        // ---- 6. write reachability.json
        ObjectNode out = json.createObjectNode();
        out.put("schema_version", "0.1");
        out.putObject("project").put("name", a.getOrDefault("project", classesDir.toString()));
        out.put("generated_at", Instant.now().toString());
        ObjectNode analysis = out.putObject("analysis");
        analysis.put("engine", "sootup");
        analysis.put("engine_version", ENGINE_VERSION);
        analysis.put("call_graph_algorithm", "CHA");
        ArrayNode ep = analysis.putArray("entry_points");
        entries.forEach(s -> ep.add(s.toString()));
        analysis.put("reachable_application_methods", reachable.size());
        analysis.put("reflection_in_reachable_code", reflection);
        out.set("results", results);
        json.writerWithDefaultPrettyPrinter().writeValue(new File(a.get("out")), out);
        System.err.printf("[engine] wrote %d results to %s%n", results.size(), a.get("out"));
    }

    // ------------------------------------------------------------------ helpers
    private static void set(ObjectNode r, String status, String reason) {
        r.put("status", status);
        r.put("reason", reason);
    }

    private static List<Call> matching(List<Call> calls, List<String[]> targets) {
        return calls.stream()
                .filter(c -> targets.stream().anyMatch(t -> t[0].equals(c.calleeClass()) && t[1].equals(c.calleeMethod())))
                .collect(Collectors.toList());
    }

    /** Curated methods for this advisory: matched on its id or an alias (e.g. a CVE), else the artifact's "*" entry. */
    static List<String[]> targetsFor(JsonNode entries, String artifact, JsonNode vuln) {
        Set<String> ids = new HashSet<>();
        ids.add(vuln.path("id").asText());
        vuln.path("aliases").forEach(x -> ids.add(x.asText()));
        JsonNode specific = null;
        JsonNode wildcard = null;
        for (JsonNode e : entries) {
            if (!artifact.equals(e.path("artifact_id").asText())) {
                continue;
            }
            String v = e.path("vulnerability").asText();
            if (ids.contains(v)) {
                specific = e;
            } else if ("*".equals(v)) {
                wildcard = e;
            }
        }
        JsonNode chosen = specific != null ? specific : wildcard;
        List<String[]> out = new ArrayList<>();
        if (chosen != null) {
            for (JsonNode m : chosen.path("methods")) {
                String[] parts = m.asText().split("#", 2);
                if (parts.length == 2) {
                    out.add(parts);
                }
            }
        }
        return out;
    }

    /** Shortest call path from any entry point to target (breadth-first over the call graph). */
    private static List<MethodSignature> pathTo(CallGraph cg, List<MethodSignature> entries, MethodSignature target) {
        Map<MethodSignature, MethodSignature> parent = new HashMap<>();
        Deque<MethodSignature> queue = new ArrayDeque<>();
        for (MethodSignature e : entries) {
            parent.put(e, null);
            queue.add(e);
        }
        while (!queue.isEmpty()) {
            MethodSignature cur = queue.poll();
            if (cur.equals(target)) {
                LinkedList<MethodSignature> path = new LinkedList<>();
                for (MethodSignature s = cur; s != null; s = parent.get(s)) {
                    path.addFirst(s);
                }
                return path;
            }
            if (!cg.containsMethod(cur)) {
                continue;
            }
            for (MethodSignature next : cg.callsFrom(cur)) {
                if (!parent.containsKey(next)) {
                    parent.put(next, cur);
                    queue.add(next);
                }
            }
        }
        return List.of(target);
    }

    static Set<String> listClassNames(Path dir) throws IOException {
        try (Stream<Path> files = Files.walk(dir)) {
            return files.filter(p -> p.toString().endsWith(".class"))
                    .map(p -> dir.relativize(p).toString())
                    .filter(n -> !n.endsWith("module-info.class") && !n.endsWith("package-info.class"))
                    .map(n -> n.substring(0, n.length() - ".class".length()).replace(File.separatorChar, '.'))
                    .collect(Collectors.toCollection(TreeSet::new));
        }
    }

    static List<Path> listJars(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.toString().endsWith(".jar")).sorted().collect(Collectors.toList());
        }
    }

    static Set<String> jarClassNames(Path jar) throws IOException {
        Set<String> names = new HashSet<>();
        try (JarFile jf = new JarFile(jar.toFile())) {
            Enumeration<JarEntry> en = jf.entries();
            while (en.hasMoreElements()) {
                String n = en.nextElement().getName();
                if (n.endsWith(".class") && !n.startsWith("META-INF/")) {
                    names.add(n.substring(0, n.length() - ".class".length()).replace('/', '.'));
                }
            }
        }
        return names;
    }

    static Map<String, String> parseArgs(String[] args) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--help") || args[i].equals("-h")) {
                m.put("help", "true");
            } else if (args[i].startsWith("--") && i + 1 < args.length) {
                m.put(args[i].substring(2), args[++i]);
            }
        }
        return m;
    }
}
