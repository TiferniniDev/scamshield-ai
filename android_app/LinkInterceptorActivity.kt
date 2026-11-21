package ai.scamshield.mobile

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * ScamShield AI - Native Android Pre-Click Link Interceptor
 * Automatically checks links tapped in WhatsApp, SMS, or Google Maps against
 * the ScamShield AI API before handing safe links off to Chrome.
 */
class LinkInterceptorActivity : Activity() {

    private val apiEndpoint = "https://api.scamshield.local/api/analyze"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val targetUri: Uri? = intent?.data
        if (targetUri == null) {
            finish()
            return
        }
        checkAndHandle(targetUri.toString())
    }

    private fun checkAndHandle(targetUrl: String) {
        thread {
            val result = callScamShieldApi(targetUrl)
            val verdict = result.optString("verdict", "SUSPICIOUS")
            val reason = result.optJSONArray("reasons_en")?.optString(0) ?: "Unverified link."

            runOnUiThread {
                when (verdict) {
                    "SAFE" -> openInBrowser(targetUrl)
                    "FRAUD" -> showAlert("Fraud Blocked", "This link is flagged as high-risk fraud.\n\n$reason", targetUrl, allowProceed = false)
                    else -> showAlert("Suspicious Link", "Proceed with caution.\n\n$reason", targetUrl, allowProceed = true)
                }
            }
        }
    }

    private fun callScamShieldApi(targetUrl: String): JSONObject {
        return try {
            val conn = URL(apiEndpoint).openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 2500
            conn.readTimeout = 3000
            val body = JSONObject().apply {
                put("url", targetUrl)
                put("source", "citizen_bot")
                put("source_label", "Android Link Interceptor")
                put("deep_scan", true)
            }
            conn.outputStream.use { it.write(body.toString().toByteArray()) }
            val text = conn.inputStream.bufferedReader().readText()
            JSONObject(text)
        } catch (_: Exception) {
            JSONObject().put("verdict", "SUSPICIOUS")
        }
    }

    private fun showAlert(title: String, msg: String, targetUrl: String, allowProceed: Boolean) {
        val builder = AlertDialog.Builder(this)
            .setTitle("ScamShield AI — $title")
            .setMessage(msg)
            .setNegativeButton("Stay Safe") { _, _ -> finish() }
            .setOnCancelListener { finish() }

        if (allowProceed) {
            builder.setPositiveButton("Open Anyway") { _, _ -> openInBrowser(targetUrl) }
        }
        builder.show()
    }

    private fun openInBrowser(targetUrl: String) {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(targetUrl)).apply {
            setPackage("com.android.chrome")
        }
        try {
            startActivity(intent)
        } catch (_: Exception) {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(targetUrl)))
        }
        finish()
    }
}
