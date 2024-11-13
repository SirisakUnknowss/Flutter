package com.example.flutter_application_1

import android.annotation.SuppressLint
import android.app.Activity
import android.app.ActivityManager
import android.app.ActivityManager.AppTask
import android.app.Application
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Parcelable
import android.os.Process
import android.text.TextUtils
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.vkey.android.internal.vguard.engine.BasicThreatInfo
import com.vkey.android.vguard.ActivityLifecycleHook
import com.vkey.android.vguard.LocalBroadcastManager
import com.vkey.android.vguard.MemoryConfiguration
import com.vkey.android.vguard.VGExceptionHandler
import com.vkey.android.vguard.VGuard
import com.vkey.android.vguard.VGuardBroadcastReceiver
import com.vkey.android.vguard.VGuardBroadcastReceiver.VGUARD_OVERLAY_DETECTED
import com.vkey.android.vguard.VGuardBroadcastReceiver.VGUARD_SCREEN_SHARING_DETECTED
import com.vkey.android.vguard.VGuardBroadcastReceiver.VGUARD_SIDELOADED_APP_WITH_ACCESSIBILITY_PERMISSION_DETECTED
import com.vkey.android.vguard.VGuardBroadcastReceiver.VGUARD_STATUS
import com.vkey.android.vguard.VGuardBroadcastReceiver.VGUARD_VIRTUAL_SPACE_DETECTED
import com.vkey.android.vguard.VGuardBroadcastReceiver.VOS_READY
import com.vkey.android.vguard.VGuardFactory
import com.vkey.android.vguard.VGuardLifecycleHook
import org.json.JSONArray
import org.json.JSONObject
import vkey.android.vos.VosWrapper
import com.example.flutter_application_1.VkeyErrorCode.VK_VOS_INIT
import kotlin.system.exitProcess


/**
 * Filename: null.java
 * Created by lent on 24/05/2023.
 */
@SuppressLint("StaticFieldLeak")
object VKeyAppProtection : VGExceptionHandler, Application.ActivityLifecycleCallbacks {
    private val PROFILE_LOADED_ACTION = "vkey.android.vguard.PROFILE_LOADED"

    // LifecycleHook to notify VGuard of activity's lifecycle
    open var vGuardMgr: VGuard? = null
    private var hook: VGuardLifecycleHook? = null
    private var mContext: Context? = null
    // For VGuard to notify host app of events
    private var broadcastRvcr: VGuardBroadcastReceiver? = null
    private var vguardCallback: VguardCallback? = null
    private var threadIntelligenceUrl:String = ""
        set(value) {
            field = value
        }

    private var _currActivity = 0



    fun initVGuardBroadcastReceiver() {
        if (broadcastRvcr != null) return
        Log.d(TAG, "initialize  VGuardBroadcastReceiver")
        broadcastRvcr = object : VGuardBroadcastReceiver(null) {
            override fun onReceive(context: Context, intent: Intent) {
                super.onReceive(context, intent)
                if (PROFILE_LOADED_ACTION == intent.getAction()) {
                    printLogs("Profile loaded...")
                    getVGuardInstance()

                }
                else if (VOS_READY == intent.getAction()) {
                    val firmwareReturnCode: Long = intent.getLongExtra(
                        "vkey.android.vguard.FIRMWARE_RETURN_CODE", 0
                    )
                    val endTime = System.currentTimeMillis()
                    val delta = endTime - startTime
                    printLogs("VOS_READY### TIME: $delta")
                    printLogs("v-os return code: $firmwareReturnCode")
                    getVGuardInstance()
                    vosStatus = firmwareReturnCode.toInt()
                    if (vguardCallback != null) {
                        vguardCallback!!.vosReady(firmwareReturnCode)
                    }
                    if (firmwareReturnCode < -999) {
                        showWarningAlert(context, "Found threat on device, app will be quit", true)
                    }

                    // set TI URL
                    if (!TextUtils.isEmpty(threadIntelligenceUrl)) {
                        printLogs("setThreatIntelligenceServerURL 11111: " + threadIntelligenceUrl);
                        vGuardMgr?.setThreatIntelligenceServerURL(threadIntelligenceUrl);
                    }
                }
                else if (ACTION_SCAN_COMPLETE == intent.action) {
                    val endTime = System.currentTimeMillis()
                    val delta = endTime - startTime
                    printLogs("[ACTION_SCAN_COMPLETE]### TIME: $delta")
                    val builder = StringBuilder()
                    for (info in intent.getParcelableArrayListExtra<Parcelable>(
                        SCAN_COMPLETE_RESULT
                    )!!) {
                        val threatInfo: BasicThreatInfo = info as BasicThreatInfo
                        val threatClass: String = threatInfo.threatClass

                        if (info.threatClass == "1100") {
                            val infoStr = info.toString()
                            builder.append(infoStr).append("\n")
                        } else if ("1000".equals(threatClass, ignoreCase = true)) {
                            // TODO: THREAT_ROOT_JAILBREAK
                        } else if ("2000".equals(threatClass, ignoreCase = true)) {
                            // TODO: THREAT_RATS
                        } else if ("3000".equals(threatClass, ignoreCase = true)) {
                            // TODO: THREAT_APPLICATION_TAMPERING
                        } else if ("4000".equals(threatClass, ignoreCase = true)) {
                            // TODO: THREAT_RUNTIME_TAMPERING
                        } else if ("5000".equals(threatClass, ignoreCase = true)) {
                            // TODO: THREAT_LIBRARIES_TAMPERING
                        } else if ("6000".equals(threatClass, ignoreCase = true)) {
                            // TODO: THREAT_MALWARE
                        }
                        val infoStr: String = threatInfo.toString()
                        builder.append(infoStr).append("\n")
                    }
                    printLogs("Action Scan Complete: $builder")
                }
                else if (VGUARD_SCREEN_SHARING_DETECTED == intent.getAction()) {
//                    val sharingDisplays: ArrayList<String> =
//                        intent.getStringArrayListExtra(VGUARD_SCREEN_SHARING_DISPLAY_NAMES) as ArrayList<String>
//                    val builder = StringBuilder()
//                    for (sharingDisplay in sharingDisplays) {
//                        builder.append(sharingDisplay).append("\n")
//                    }
                    val sharingDisplays = intent.getStringExtra(VGUARD_SCREEN_SHARING_DISPLAY_NAMES)
                    val jsonArray = JSONArray(sharingDisplays)
                    Log.d(TAG, "Screen Sharing Detected by: \n$jsonArray")
                    // printLogs("Screen Sharing Detected by: \n$builder")
                    showWarningAlert(context, "Screen Sharing Detected by: \n$jsonArray", false)
                }
                else if (VGUARD_SIDELOADED_APP_WITH_ACCESSIBILITY_PERMISSION_DETECTED == intent.getAction()) {
                    val builder = java.lang.StringBuilder()
                    builder.append("\n\nSideLoad Detected")
                    try {
                        val sideloadlist = intent.getStringExtra(VGUARD_SIDELOADED_RESULT)
                        if (!TextUtils.isEmpty(sideloadlist)) {
                            val jsonArray = JSONArray(sideloadlist)
                            if (jsonArray != null) {
                                for (i in 0 until jsonArray.length()) {
                                    builder.append("\n${jsonArray.optJSONObject(i)}")
                                }
                            }
                        } else {
                            val packageID =
                                intent.getStringExtra("vkey.android.vguard.VGUARD_SIDELOADED_PACKAGE_ID")
                            val source =
                                intent.getStringExtra("vkey.android.vguard.VGUARD_SIDELOADED_SOURCE")
                            builder.append("\nPackageID: $packageID")
                            builder.append("\nSource Install: $source")
                        }
                    } catch (e: java.lang.Exception) { }

                    showWarningAlert(context, builder.toString(), false)
                }
                else if (VGUARD_OVERLAY_DETECTED == intent.getAction()) {
                    showWarningAlert(context, "An overlay view was detected!", false)
                }
                else if (VGUARD_VIRTUAL_SPACE_DETECTED == intent.getAction()) {
                    showWarningAlert(context, "Virtual space Detected!", false)
                }
                else if (VGUARD_STATUS == intent.getAction()) {
                    if (intent.hasExtra(VGUARD_INIT_STATUS)) {
                        val initStatus: Boolean = intent.getBooleanExtra(VGUARD_INIT_STATUS, false)
                        var msg = "$VGUARD_STATUS:$initStatus"
                        if (!initStatus) {
                            try {
                                val jsonObject =
                                    JSONObject(intent.getStringExtra(VGUARD_MESSAGE))
                                Log.d(TAG, jsonObject.getString("code"))
                                Log.d(TAG, jsonObject.getString("description"))
                                msg += " $jsonObject"
                            } catch (e: Exception) {
                            }
                        }
                        printLogs(msg)
                    }
                }
            }
        }

        // register using LocalBroadcastManager only for keeping data within your app
        val localBroadcastMgr = LocalBroadcastManager.getInstance(mContext)
        localBroadcastMgr.registerReceiver(
            broadcastRvcr,
            IntentFilter(VGuardBroadcastReceiver.ACTION_SCAN_COMPLETE)
        )
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(PROFILE_LOADED_ACTION))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VOS_READY))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGUARD_OVERLAY_DETECTED));
        // localBroadcastMgr.registerReceiver(broadcastRvcr, new IntentFilter(VGUARD_OVERLAY_DETECTED_DISABLE));
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGUARD_VIRTUAL_SPACE_DETECTED));
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGUARD_SCREEN_SHARING_DETECTED))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGUARD_SIDELOADED_APP_WITH_ACCESSIBILITY_PERMISSION_DETECTED))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGUARD_STATUS))

    }

    fun setThreatIntelligenceServerURL(tiUrl: String) {
        printLogs("setThreatIntelligenceServerURL: $tiUrl")
        threadIntelligenceUrl = tiUrl
        if (!TextUtils.isEmpty(tiUrl)) {
            if(vGuardMgr != null) {
                vGuardMgr?.setThreatIntelligenceServerURL(tiUrl)
            }
        }
    }

    fun setTlaUrl(context: Context?, tlaUrl: String) {
        if (!TextUtils.isEmpty(tlaUrl)) {
            printLogs("setLoggerBaseUrl: $tlaUrl")
            // VosWrapper.getInstance(context).setLoggerBaseUrl("tlaUrl")
        }
    }

    var startTime:Long = 0
    fun setupVGuard(context: Context?) {
        if (vGuardMgr != null) return
        mContext = context
        initVGuardBroadcastReceiver()
        try {
            Log.d(TAG, "setupVGuard called")
            vosStatus = VK_VOS_INIT
            // set TI URL
            startTime = System.currentTimeMillis()
            VGuardFactory().getVGuard(
                mContext,
                VGuardFactory.Builder().apply {
                    isAllowsArbitraryNetworking = false
                    memoryConfiguration = MemoryConfiguration.HIGH
                    setVGExceptionHandler{ cause ->
                        handleException(cause)
                }})
        } catch (e: Exception) {
            Log.e(TAG, "A serious exception has occurred within V-Guard", e)
        }
    }

    override fun handleException(e: Exception) {
        getVGuardInstance()
        val sVGuardErrorCode = e.message
        printLogs("An exception happened in V-Guard: $sVGuardErrorCode")
        if("20050".equals(sVGuardErrorCode, true) ||
            "-1039".equals(sVGuardErrorCode, true)) {
            showWarningAlert(mContext, "Emulator is detected: $sVGuardErrorCode", false);
            printLogs("Emulator is detected: $sVGuardErrorCode");
        }
    }

    // necessary for VGuard to be informed of the activity's lifecycle
    private fun getVGuardInstance() {
        if (vGuardMgr == null) {
            vGuardMgr = VGuardFactory.getInstance()
            // necessary for VGuard to be informed of the activity's lifecycle
            hook = ActivityLifecycleHook(vGuardMgr)
            Log.i(TAG, "vGuardMgr: getVGuardInstance");
        }
    }

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
    override fun onActivityCreated(activity: Activity, bundle: Bundle?) {
        _currActivity++
//        if (vGuardMgr == null && activity is MainActivity) {
//             setupVGuard(activity.getApplicationContext())
//        }
    }

    override fun onActivityStarted(activity: Activity) {}
    override fun onActivityResumed(activity: Activity) {
        if (vGuardMgr != null) {
            try {
                vGuardMgr?.onResume(hook, activity)
            } catch (e: java.lang.Exception) { }
        }
    }

    override fun onActivityPaused(activity: Activity) {
        try {
            vGuardMgr?.onPause(hook)
        } catch (e: java.lang.Exception) {}
    }

    override fun onActivityStopped(activity: Activity) {}
    override fun onActivityDestroyed(activity: Activity) {
        _currActivity--
        Log.d(TAG, "onActivityDestroyed: $_currActivity")
        if (_currActivity <= 0) {
            // VkeyCryptoTA.unloadTA()
            destroyVguard()
        }
    }

    fun destroyVguard() {
        if (broadcastRvcr != null) {
            try {
                LocalBroadcastManager.getInstance(mContext).unregisterReceiver(broadcastRvcr)
            } catch (e: Exception) {
            } finally {
                broadcastRvcr = null
            }
        }
        if (vGuardMgr != null) {
            // Stop VKEY
            Log.d(TAG, "------ destroy Vguard")
            vGuardMgr!!.destroy()
            vGuardMgr = null
        }
        _currActivity = 0
        vosStatus = VK_VOS_INIT
    }

    const val autoQuitIntervalInMilliseconds = 3000
    private fun showWarningAlert(context: Context?, message: String, autoQuit: Boolean) {
        if (context == null) {
            Log.e(TAG, "No context to show Warning alert")
        }
        // Toast.makeText(context, message, Toast.LENGTH_LONG).show()
        try {
            val builder: AlertDialog.Builder? = context?.let { AlertDialog.Builder(it) }
            builder?.setMessage(message)
            builder?.setTitle("Alert !")
            builder?.setCancelable(false)
            builder?.setPositiveButton("OK") { dialog: DialogInterface?, which: Int ->
                if(autoQuit) {
                    dialog?.dismiss()
                    quitApp();
                }
            }
            val alertDialog: AlertDialog? = builder?.create()
            alertDialog?.show()
        } catch (e: Exception) {
            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
        }

        if(autoQuit) {
            Handler().postDelayed({ quitApp() }, autoQuitIntervalInMilliseconds.toLong())
        }
    }

    private fun quitApp() {
        destroyVguard()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            val am = mContext?.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            if (am != null) {
                var appTaskList: List<AppTask>? = null
                appTaskList = am.appTasks
                if (appTaskList != null && !appTaskList.isEmpty()) {
                    val appTask = appTaskList[0]
                    appTask.finishAndRemoveTask()
                }
            }
        } else {
            // Exit the application
            exitProcess(0)
        }
    }

    private fun printLogs(logs: String) {
        Log.d(TAG, logs)
//        EventBus.getDefault().post(logs)
    }

    val LAST_ISOLATED_UID = 99999
    val PER_USER_RANGE = 100000
    val LAST_APP_ZYGOTE_ISOLATED_UID = 98999
    val FIRST_APP_ZYGOTE_ISOLATED_UID = 90000
    val FIRST_ISOLATED_UID = 99000
    val isIsolatedProcess: Boolean
        get() = isIsolated(Process.myUid())

    private fun isIsolated(uid: Int): Boolean {
        var uid = uid
        uid %= PER_USER_RANGE
        return uid in FIRST_ISOLATED_UID..LAST_ISOLATED_UID || uid in FIRST_APP_ZYGOTE_ISOLATED_UID..LAST_APP_ZYGOTE_ISOLATED_UID
    }

    fun setVguardCallback(vguardCallback: VguardCallback?) {
        VKeyAppProtection.vguardCallback = vguardCallback
    }

    fun isVosRunning(context: Context) : Boolean{
        val rs = VosWrapper.getInstance(context).execute { }

        return (rs < 1)
    }

    interface VguardCallback {
        fun vosReady(firmwareReturnCode: Long)
    }

    var vosStatus: Int = VkeyErrorCode.VK_VOS_INIT
    const val TAG = "VKeyLog"


}