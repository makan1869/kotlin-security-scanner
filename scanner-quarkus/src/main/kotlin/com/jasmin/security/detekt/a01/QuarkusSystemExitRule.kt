package com.jasmin.security.detekt.a01

import com.jasmin.security.detekt.core.SecurityRule
import dev.detekt.api.Config
import org.jetbrains.kotlin.psi.KtCallExpression
import org.jetbrains.kotlin.psi.KtDotQualifiedExpression

class QuarkusSystemExitRule(config: Config) : SecurityRule(
    config,
    id = "QuarkusSystemExit",
    description = "Korištenje System.exit() u web aplikaciji može srušiti server!",
) {
    override fun visitCallExpression(expression: KtCallExpression) {
        super.visitCallExpression(expression)

        val calleeText = expression.calleeExpression?.text ?: return

        // 1. Slučaj: exitProcess(0) -> poziva se direktno
        val isExitProcess = calleeText == "exitProcess"

        // 2. Slučaj: System.exit(1) -> provjeravamo roditelja (KtDotQualifiedExpression)
        val parent = expression.parent
        val isSystemExit = calleeText == "exit" && parent is KtDotQualifiedExpression &&
                (parent.receiverExpression.text == "System" || parent.receiverExpression.text == "java.lang.System")

        if (isExitProcess || isSystemExit) {
            reportAt(expression, "Dangerous application shutdown call (exit) detected. An attacker could cause a Denial of Service (DoS)!")
        }
    }
}