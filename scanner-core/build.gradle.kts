// Framework-agnostic rules — SQL injection, weak crypto, path traversal,
// hardcoded secrets, insecure random, SSRF, sensitive logging.
// No framework dependencies: works with any Kotlin project.

plugins {
    id("com.vanniktech.maven.publish")
    `java-test-fixtures`
}

dependencies {
    "testFixturesImplementation"("dev.detekt:detekt-api:2.0.0-alpha.6")
    "testFixturesImplementation"("org.assertj:assertj-core:3.26.3")
    "testFixturesImplementation"("org.snakeyaml:snakeyaml-engine:2.10")
}

mavenPublishing {
    pom {
        name = "Kotlin Security Scanner — Core"
        description = "Detekt rules for OWASP Top 10 security vulnerabilities in Kotlin: " +
            "SQL/command injection, weak crypto, path traversal, hardcoded credentials, " +
            "insecure random, SSRF, unsafe deserialization, and sensitive data logging. " +
            "Framework-agnostic — works with any Kotlin/JVM project."
    }
}

afterEvaluate {
    val javaComponent = components["java"] as AdhocComponentWithVariants
    listOf("testFixturesApiElements", "testFixturesRuntimeElements", "testFixturesSourcesElements")
        .mapNotNull { configurations.findByName(it) }
        .forEach { javaComponent.withVariantsFromConfiguration(it) { skip() } }
}
