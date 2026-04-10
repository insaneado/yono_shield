package com.example.yono_shield

// ============================================================================
// YONO SHIELD — PackageScannerService.kt
// ============================================================================
// PILLAR 1: Clone Radar
//
// This service queries the Android PackageManager to scan all installed
// applications. It cross-references each app against a threat database of
// known fake banking app package names and checks whether the app was
// installed from the Google Play Store or from an unknown (sideloaded) source.
//
// RISK LEVELS:
//   DANGEROUS   — Package name matches a known fake/malicious banking app
//   SUSPICIOUS  — App was sideloaded (not installed from Play Store)
//   SAFE        — Installed from Play Store, no threat match
// ============================================================================

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

class PackageScannerService(private val context: Context) {

    // ========================================================================
    // THREAT DATABASE
    // Known fake/malicious banking app package names.
    // In production, this would be fetched from a remote threat intelligence
    // API. For the hackathon, we use a hardcoded list.
    // ========================================================================
    companion object {
        val THREAT_DATABASE: Map<String, String> = mapOf(
            // Fake SBI clones
            "com.sbi.fake" to "Fake SBI Clone",
            "com.sbi.lotmoney" to "SBI Lottery Scam",
            "com.fake.sbi.yono" to "Fake YONO SBI",
            "com.sbi.reward.app" to "SBI Reward Scam",

            // Fake ICICI clones
            "com.icici.phish" to "ICICI Phishing App",
            "com.icici.imobile.fake" to "Fake iMobile",

            // Fake HDFC clones
            "com.hdfc.fake" to "Fake HDFC NetBanking",
            "com.hdfc.loan.instant" to "HDFC Instant Loan Scam",

            // Fake payment apps
            "com.fake.gpay" to "Fake Google Pay",
            "com.fake.phonepe" to "Fake PhonePe",
            "com.fake.paytm" to "Fake Paytm Clone",

            // Generic malware package patterns
            "com.loan.instant.approval" to "Predatory Loan App",
            "com.free.recharge.unlimited" to "Recharge Scam App",
            "com.kyc.update.now" to "KYC Phishing App",
            "com.bank.update.required" to "Bank Update Phishing"
        )

        // Known legitimate installer packages (trusted sources)
        val TRUSTED_INSTALLERS = setOf(
            "com.android.vending",        // Google Play Store
            "com.google.android.feedback", // Google Play (alternate)
            "com.amazon.venezia",          // Amazon App Store
            "com.sec.android.app.samsungapps", // Samsung Galaxy Store
            "com.huawei.appmarket",        // Huawei AppGallery
            "com.xiaomi.market"            // Xiaomi GetApps
        )
    }

    // ========================================================================
    // scanAllApps()
    // 
    // Queries PackageManager for all installed applications and evaluates
    // each one for risk level. Returns a list of maps suitable for JSON
    // serialization and transmission to Flutter via MethodChannel.
    // ========================================================================
    fun scanAllApps(): List<Map<String, Any>> {
        val pm = context.packageManager
        val results = mutableListOf<Map<String, Any>>()

        // Get all installed applications (requires QUERY_ALL_PACKAGES)
        val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)

        for (appInfo in installedApps) {
            // Skip system apps that are part of the OS framework to reduce noise
            if (isSystemFrameworkApp(appInfo)) continue

            val packageName = appInfo.packageName
            val appName = pm.getApplicationLabel(appInfo).toString()
            val installerSource = getInstallerPackageName(pm, packageName)
            val isTrustedSource = TRUSTED_INSTALLERS.contains(installerSource)

            // Determine risk level
            val (riskLevel, riskReason) = evaluateRisk(packageName, isTrustedSource, installerSource)

            results.add(
                mapOf(
                    "packageName" to packageName,
                    "appName" to appName,
                    "installerSource" to (installerSource ?: "Unknown / Sideloaded"),
                    "isTrustedSource" to isTrustedSource,
                    "riskLevel" to riskLevel,
                    "riskReason" to riskReason
                )
            )
        }

        // Sort: DANGEROUS first, then SUSPICIOUS, then SAFE
        val riskOrder = mapOf("DANGEROUS" to 0, "SUSPICIOUS" to 1, "SAFE" to 2)
        results.sortBy { riskOrder[it["riskLevel"] as String] ?: 3 }

        return results
    }

    // ========================================================================
    // evaluateRisk()
    //
    // Cross-references the package name against the threat database and
    // checks the installation source to assign a risk level.
    // ========================================================================
    private fun evaluateRisk(
        packageName: String,
        isTrustedSource: Boolean,
        installerSource: String?
    ): Pair<String, String> {
        // CHECK 1: Does the package name match a known threat?
        val threatMatch = THREAT_DATABASE[packageName]
        if (threatMatch != null) {
            return Pair("DANGEROUS", "Known malicious app: $threatMatch")
        }

        // CHECK 2: Does the package name contain suspicious banking keywords
        // combined with non-trusted installation source?
        val suspiciousKeywords = listOf("bank", "sbi", "icici", "hdfc", "axis",
            "kotak", "upi", "gpay", "paytm", "phonepe", "loan", "kyc")
        val containsBankingKeyword = suspiciousKeywords.any {
            packageName.lowercase().contains(it)
        }
        if (containsBankingKeyword && !isTrustedSource) {
            return Pair("DANGEROUS", "Banking-related app from untrusted source: ${installerSource ?: "Sideloaded"}")
        }

        // CHECK 3: Is the app sideloaded (not from a trusted installer)?
        if (!isTrustedSource) {
            return Pair("SUSPICIOUS", "Installed from: ${installerSource ?: "Unknown source (sideloaded)"}")
        }

        // DEFAULT: App is from a trusted source and not in the threat database
        return Pair("SAFE", "Installed from trusted source")
    }

    // ========================================================================
    // getInstallerPackageName()
    //
    // Retrieves the package name of the app that installed a given package.
    // Uses the modern API on Android 11+ and falls back for older versions.
    // ========================================================================
    private fun getInstallerPackageName(pm: PackageManager, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Android 11+ — Use InstallSourceInfo for more granular data
                val sourceInfo = pm.getInstallSourceInfo(packageName)
                sourceInfo.installingPackageName
            } else {
                // Legacy fallback for Android < 11
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        } catch (e: Exception) {
            // Package not found or installer info unavailable
            null
        }
    }

    // ========================================================================
    // isSystemFrameworkApp()
    //
    // Filters out core Android system framework apps (e.g., com.android.systemui)
    // that are not relevant to security scanning. We keep non-framework system
    // apps (like pre-installed OEM apps) as they can still be sideloaded threats.
    // ========================================================================
    private fun isSystemFrameworkApp(appInfo: ApplicationInfo): Boolean {
        // Only filter out apps that are BOTH system apps AND have no launch intent
        // This removes framework components but keeps user-visible pre-installed apps
        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val hasLaunchIntent = context.packageManager.getLaunchIntentForPackage(appInfo.packageName) != null

        // Keep the app if it has a launch intent (user-visible), even if it's a system app
        return isSystem && !hasLaunchIntent
    }
}
