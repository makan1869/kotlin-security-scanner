package com.jasmin.security.detekt

import com.jasmin.security.detekt.core.assertShippedConfigActivatesEveryRule
import org.junit.jupiter.api.Test

class DropwizardRuleSetProviderTest {

    @Test
    fun `shipped config activates every registered rule`() {
        assertShippedConfigActivatesEveryRule(DropwizardRuleSetProvider())
    }
}
