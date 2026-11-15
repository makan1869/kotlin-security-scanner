plugins {
    kotlin("jvm") version "2.4.10" apply false
    id("dev.detekt") version "2.0.0-alpha.6" apply false
    id("com.vanniktech.maven.publish") version "0.37.0" apply false
}

allprojects {
    group = "io.github.makan1869"
    version = "0.4.0"
    repositories { mavenCentral() }
}

// ── Root-level security tasks ──────────────────────────────────────────────────
//
// generateSecurityBaseline — snapshot current findings into each module's detekt-baseline.xml.
//   Brownfield teams run this once to accept existing issues. Subsequent checkSecurity calls
//   only fail on *new* findings introduced after the snapshot.
//
// checkSecurity — run the full security scan with the active baseline.
//   New findings fail the build; baselined ones are silently skipped.

tasks.register("generateSecurityBaseline") {
    group = "security"
    description = "Snapshot current security findings as the baseline (new violations will still fail)."
    dependsOn(subprojects.filter { it.name != "scanner-e2e" }.map { "${it.path}:detektBaseline" })
    doLast {
        println("Security baselines written to each module's detekt-baseline.xml")
        println("Commit this file so CI enforces only regressions, not pre-existing issues.")
    }
}

tasks.register("checkSecurity") {
    group = "security"
    description = "Security scan — only findings absent from the baseline cause a failure."
    dependsOn(subprojects.map { "${it.path}:detekt" })
}

// ── e2e module — detekt-only, no Kotlin compilation, ignoreFailures ───────────
project(":scanner-e2e") {
    apply(plugin = "dev.detekt")

    dependencies {
        "detektPlugins"(project(":scanner-core"))
        "detektPlugins"(project(":scanner-spring-boot"))
        "detektPlugins"(project(":scanner-quarkus"))
        "detektPlugins"(project(":scanner-dropwizard"))
        "detektPlugins"(project(":scanner-ktor"))
        "detektPlugins"(project(":scanner-micronaut"))
        "detektPlugins"(project(":scanner-vertx"))
        "detektPlugins"("dev.detekt:detekt-rules-ktlint-wrapper:2.0.0-alpha.6")
    }

    extensions.configure<dev.detekt.gradle.extensions.DetektExtension> {
        config.setFrom(rootProject.files("config/detekt/detekt.yml"))
        buildUponDefaultConfig = false
        source.setFrom("src/main/kotlin")
    }

    tasks.withType<dev.detekt.gradle.Detekt>().configureEach {
        ignoreFailures = true  // intentionally vulnerable code — we want the report, not a build failure
        reports {
            html.required.set(true)
            sarif.required.set(true)
        }
    }
}

subprojects {
    if (name == "scanner-e2e") return@subprojects

    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "dev.detekt")

    val detektVersion = "2.0.0-alpha.6"

    extensions.configure<JavaPluginExtension> {
        targetCompatibility = JavaVersion.VERSION_21
    }

    extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
            freeCompilerArgs.addAll("-Xjsr305=strict")
        }
    }

    configurations.all {
        exclude(group = "org.slf4j", module = "slf4j-simple")
    }
    configurations.named("testRuntimeClasspath") {
        exclude(group = "org.jetbrains.kotlin", module = "kotlin-main-kts")
    }

    dependencies {
        "compileOnly"("dev.detekt:detekt-api:$detektVersion")
        "detektPlugins"("dev.detekt:detekt-rules-ktlint-wrapper:$detektVersion")
        "testImplementation"("dev.detekt:detekt-test:$detektVersion")
        "testImplementation"("dev.detekt:detekt-test-assertj:$detektVersion")
        "testImplementation"(testFixtures(project(":scanner-core")))
        "testImplementation"("org.assertj:assertj-core:3.26.3")
        "testImplementation"("org.junit.jupiter:junit-jupiter:5.11.0")
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }

    tasks.withType<Test> { useJUnitPlatform() }

    extensions.configure<dev.detekt.gradle.extensions.DetektExtension> {
        config.setFrom(rootProject.files("config/detekt/detekt.yml"))
        buildUponDefaultConfig = true
        source.setFrom("src/main/kotlin", "src/test/kotlin")
        baseline = file("detekt-baseline.xml")
    }

    tasks.withType<dev.detekt.gradle.Detekt>().configureEach {
        reports {
            html.required.set(true)
            sarif.required.set(true)
        }
        jvmTarget = "21"
    }

    // Shared POM metadata applied whenever a module opts into publishing
    pluginManager.withPlugin("com.vanniktech.maven.publish") {
        val signingKey = findProperty("signingInMemoryKey")?.toString()
        val signingKeyId = findProperty("signingInMemoryKeyId")?.toString()
        val signingPassword = findProperty("signingInMemoryKeyPassword")?.toString()
        val hasSigning = !signingKey.isNullOrBlank()

        // Wire in-memory GPG key only when credentials are actually present.
        // GitHub Actions sets empty string for unset secrets; calling useInMemoryPgpKeys("","","")
        // throws "key ID must be in a valid form" even before the upload attempt.
        if (hasSigning) {
            pluginManager.withPlugin("signing") {
                configure<org.gradle.plugins.signing.SigningExtension> {
                    useInMemoryPgpKeys(
                        signingKeyId?.takeIf { it.isNotBlank() },
                        signingKey,
                        signingPassword,
                    )
                }
            }
        }

        configure<com.vanniktech.maven.publish.MavenPublishBaseExtension> {
            publishToMavenCentral()
            if (hasSigning) signAllPublications()
            pom {
                url = "https://github.com/makan1869/kotlin-security-scanner"
                inceptionYear = "2024"
                licenses {
                    license {
                        name = "Apache-2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0"
                        distribution = "repo"
                    }
                }
                developers {
                    developer {
                        id = "JasminGuberinic"
                        name = "Jasmin Guberinic"
                        email = "jasmin.guberinic@gmail.com"
                    }
                    developer {
                        id = "makan1869"
                        name = "Makan Sepehrifar"
                    }
                }
                scm {
                    url = "https://github.com/makan1869/kotlin-security-scanner"
                    connection = "scm:git:git://github.com/makan1869/kotlin-security-scanner.git"
                    developerConnection =
                        "scm:git:ssh://git@github.com/makan1869/kotlin-security-scanner.git"
                }
            }
        }
    }
}
