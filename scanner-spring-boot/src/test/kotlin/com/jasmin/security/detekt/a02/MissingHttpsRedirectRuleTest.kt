package com.jasmin.security.detekt.a02

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MissingHttpsRedirectRuleTest {

    private val rule = MissingHttpsRedirectRule(Config.empty)

    // ── Positive — must flag ──────────────────────────────────────────────────

    @Test
    fun `flags SecurityFilterChain bean without requiresChannel`() {
        val code = """
            @Bean
            fun filterChain(http: HttpSecurity): SecurityFilterChain {
                http.authorizeHttpRequests { it.anyRequest().authenticated() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags SecurityFilterChain with only CSRF config`() {
        val code = """
            @Bean
            fun securityChain(http: HttpSecurity): SecurityFilterChain {
                http.csrf { it.disable() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    // ── Negative — must NOT flag ──────────────────────────────────────────────

    @Test
    fun `ignores SecurityFilterChain with requiresChannel`() {
        val code = """
            @Bean
            fun filterChain(http: HttpSecurity): SecurityFilterChain {
                http.requiresChannel { it.anyRequest().requiresSecure() }
                http.authorizeHttpRequests { it.anyRequest().authenticated() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores SecurityFilterChain with requiresSecure`() {
        val code = """
            @Bean
            fun chain(http: HttpSecurity): SecurityFilterChain {
                http.portMapper { it.http(8080).mapsTo(8443) }
                    .requiresChannel { it.anyRequest().requiresSecure() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores non-Bean function returning SecurityFilterChain`() {
        val code = """
            fun makeChain(http: HttpSecurity): SecurityFilterChain {
                http.authorizeHttpRequests { it.anyRequest().authenticated() }
                return http.build()
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    // ── Isolation ─────────────────────────────────────────────────────────────

    @Test
    fun `does not trigger on DisabledHttpSecurity fixture`() {
        val code = """
            fun configure(http: HttpSecurity) {
                http.authorizeHttpRequests { auth ->
                    auth.anyRequest().permitAll()
                }
            }
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
