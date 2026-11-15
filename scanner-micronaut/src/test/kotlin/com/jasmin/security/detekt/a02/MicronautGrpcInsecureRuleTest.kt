package com.jasmin.security.detekt.a02

import dev.detekt.api.Config
import dev.detekt.test.lint
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class MicronautGrpcInsecureRuleTest {

    private val rule = MicronautGrpcInsecureRule(Config.empty)

    @Test
    fun `flags ManagedChannelBuilder with usePlaintext`() {
        val code = """
            import io.grpc.ManagedChannelBuilder
            fun channel() = ManagedChannelBuilder.forAddress("service", 8080)
                .usePlaintext()
                .build()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `flags NettyChannelBuilder with usePlaintext`() {
        val code = """
            import io.grpc.netty.NettyChannelBuilder
            fun channel() = NettyChannelBuilder.forAddress("service", 8080)
                .usePlaintext()
                .build()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).hasSize(1)
    }

    @Test
    fun `ignores ManagedChannelBuilder without usePlaintext`() {
        val code = """
            import io.grpc.ManagedChannelBuilder
            fun channel() = ManagedChannelBuilder.forAddress("service", 443)
                .useTransportSecurity()
                .build()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }

    @Test
    fun `ignores channel builder with TLS configured`() {
        val code = """
            import io.grpc.ManagedChannelBuilder
            fun channel() = ManagedChannelBuilder.forAddress("service", 443).build()
        """.trimIndent()
        assertThat(rule.lint(code, compile = false)).isEmpty()
    }
}
