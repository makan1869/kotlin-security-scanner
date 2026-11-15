package com.jasmin.security.detekt.core

import dev.detekt.api.Config
import dev.detekt.api.RuleSetProvider
import org.assertj.core.api.Assertions.assertThat
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings

/**
 * Asserts that the module's shipped `config/config.yml` activates every rule [provider]
 * registers, except [optIn]. detekt 2 only runs rules that appear in config, so a rule missing
 * from this file would silently never run for a consumer who just adds the plugin.
 */
fun assertShippedConfigActivatesEveryRule(provider: RuleSetProvider, optIn: Set<String> = emptySet()) {
    val ruleSetId = provider.ruleSetId.value
    val load = Load(LoadSettings.builder().build())
    @Suppress("UNCHECKED_CAST")
    val ruleSet = provider.javaClass.classLoader.getResources("config/config.yml").toList()
        .map { load.loadFromString(it.readText()) as Map<String, Any> }
        .single { ruleSetId in it }
        .getValue(ruleSetId) as Map<String, Any>
    val registered = provider.instance().rules.keys.map { it.value }.toSet()
    @Suppress("UNCHECKED_CAST")
    val shipped = ruleSet.filterValues { it is Map<*, *> }.mapValues { (_, v) -> (v as Map<String, Any>)[Config.ACTIVE_KEY] }

    assertThat(ruleSet[Config.ACTIVE_KEY]).isEqualTo(true)
    assertThat(shipped.keys).containsExactlyInAnyOrderElementsOf(registered)
    assertThat(shipped.filterValues { it != true }.keys).containsExactlyInAnyOrderElementsOf(optIn)
}
