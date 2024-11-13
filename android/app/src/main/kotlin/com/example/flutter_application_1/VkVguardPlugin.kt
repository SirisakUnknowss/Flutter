package com.example.flutter_application_1


import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Parcelable
import android.text.TextUtils
import android.util.Log
import androidx.annotation.NonNull
import com.example.flutter_application_1.VKeyAppProtection.initVGuardBroadcastReceiver
import com.vkey.android.internal.vguard.engine.BasicThreatInfo
import com.vkey.android.vguard.*
import com.vkey.securefileio.*
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONArray
import org.json.JSONObject
import vkey.android.vos.VosWrapper
import java.io.File
import java.io.IOException
import java.util.*

class VkVguardPlugin() : MethodChannel.MethodCallHandler, EventChannel.StreamHandler, VGExceptionHandler {
    companion object {
        private var sInstance: VkVguardPlugin? = null

        fun getInstance(): VkVguardPlugin {
            if (sInstance == null) {
                sInstance = VkVguardPlugin()
            }
            return sInstance ?: throw IllegalStateException("")
        }
    }

    private val TAG = "VguardPlugin"
    private val vguardpluginChannel = "com.vkey.vguard/vguardplugin"
    private val vguardReceiverChannel = "com.vkey.vguard/vguardreceiver"

    private lateinit var channel: MethodChannel
    private var messageChannel: EventChannel? = null
    var eventSink: EventChannel.EventSink? = null
    var scanCompleteCount = 0
    var arrayThreat = mutableListOf<Map<String,String>>()
        set(value) {
            field = value
        }

    fun initChannels(@NonNull flutterEngine: FlutterEngine) {
        // TODO: setup V-OS App Protection here,
        // see steps that follow
        channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, vguardpluginChannel)
        channel.setMethodCallHandler(this)

        messageChannel = EventChannel(flutterEngine.dartExecutor.binaryMessenger, vguardReceiverChannel)
        messageChannel?.setStreamHandler(this)
    }

    // Event Channel
    override fun onListen(arguments: Any?, eventSink: EventChannel.EventSink?) {
        this.eventSink = eventSink
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
        messageChannel = null
    }

    // Method Channel
    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: MethodChannel.Result) {
        when (call.method) {
            "setupVGuard" -> {
                setupVGuard(MainApplication.appConext)
            }
            "requestScan" -> {
                val vguard: VGuard = VGuardFactory.getInstance()
                if (vguard != null) {
                    vguard.requestScan()
                }
            }
            "sdkVersion" -> {
                val vguard: VGuard  = VGuardFactory.getInstance()
                if (vguard != null) {
                    val version = vguard.sdkVersion()
                    result.success(version)
                }
            }
            "resetVOSTrustedStorage" -> {
                val vguard: VGuard  = VGuardFactory.getInstance()
                if (vguard != null) {
                    val rs = vguard.resetVOSTrustedStorage()
                    result.success(rs)
                }
            }
            "allowsArbitraryNetworking" -> {
                val vguard: VGuard  = VGuardFactory.getInstance()
                if (vguard != null) {
                    val allow: Boolean? = call.argument("allow")
                    if(allow != null) {
                        vguard.allowsArbitraryNetworking(allow)
                    }
                }
            }
            "setLoggerBaseUrl" -> {
                val tlaUrl: String? = call.argument("url")
                 VosWrapper.getInstance(MainApplication.appConext).setLoggerBaseUrl(tlaUrl)
            }
            "forceSyncLogs" -> {
                 VosWrapper.getInstance(MainApplication.appConext).forceSyncLogs();
            }
            "decryptString" -> {
                val filename: String? = call.argument("filename")
                val password: String = call.argument("password")?:""
                if(filename != null) {
                    try {
                        val rs = _decryptString(filename?:"", password)
                        result.success(rs)
                    }
                    catch (e: Exception) {
                        result.error("Error", e.message?:e.toString(), null)
                    }
                }
                else {
                    result.error("Error", "MissingParam: filename" , null)
                }
            }
            "encryptString" -> {
                val str: String? = call.argument("str")
                val filename: String? = call.argument("filename")
                val password: String = call.argument("password")?:""
                val atomically: Boolean = call.argument("atomically")?:true
                if(str != null && filename != null) {
                    try {
                        _encryptString(str?:"", filename?:"", password, atomically)
                        result.success(true)
                    }
                    catch (e: Exception) {
                        result.error("Error", e.message?:e.toString(), null)
                    }
                }
                else {
                    result.error("Error", "MissingParam: filename" , null)
                }
            }
            else -> {
                result.notImplemented()
            }
        }
    }


    fun sendVguardEvent(eventName:String, data:Any?) {
        Log.i(TAG, "name: $eventName")
        Log.i(TAG, "data: $data")
        eventSink?.success(mutableMapOf("name" to eventName, "data" to data))
    }

    @Throws(IOException::class)
    fun _decryptString(filename: String, password: String): String {
        val file: File = File(MainApplication.appConext?.filesDir, filename)
        val sb: StringBuilder = StringBuilder()
        val rs: Int = SecureFileIO.decryptString(file.absolutePath, password, sb)
        return rs.toString()
    }

    @Throws(IOException::class)
    fun _encryptString(str:String , filename:String, password: String, atomically: Boolean){
        val file: File = File(MainApplication.appConext?.getFilesDir(), filename)
        SecureFileIO.encryptString(str, file.absolutePath, password, atomically)
    }
    /*** Init VKey SDK ----- Copy start ----- **/

    private var isVosReady = false

    private val VGUARD_EXCEPTION = "vguardException"
    open var vGuardMgr: VGuard? = null
    // LifecycleHook to notify VGuard of activity's lifecycle
    var hook: VGuardLifecycleHook? = null
    // For VGuard to notify host app of events
    private var broadcastRvcr: VGuardBroadcastReceiver? = null
    private var resetVOSTrustedStorageRvcr: VGuardBroadcastReceiver? = null

    open fun setupVGuard(context: Context?) {
        Log.d(TAG, "setupVGuard called 1")
        if (vGuardMgr != null) return
        initVGuardBroadcastReceiver()
        try {
            Log.d(TAG, "setupVGuard called")

            val builder: VGuardFactory.Builder = VGuardFactory.Builder()
                .setAllowsArbitraryNetworking(false)
                .setDebugable(false)
                .setMemoryConfiguration(MemoryConfiguration.HIGH)
                .setVGExceptionHandler(this)
            VGuardFactory().getVGuard(context, builder)
        } catch (e: Exception) {
            sendVguardEvent(VGUARD_EXCEPTION, "A serious exception has occurred within V-Guard: " + e.message)
        }
    }

    override fun handleException(p0: Exception?) {
        getVGuardInstance()
        sendVguardEvent(VGUARD_EXCEPTION, p0!!.message)
    }

    private fun getVGuardInstance() {
        if (vGuardMgr == null) {
            vGuardMgr = VGuardFactory.getInstance() as VGuard
            // necessary for VGuard to be informed of the activity's lifecycle
            hook = ActivityLifecycleHook(vGuardMgr)
            Log.i(TAG, "vGuardMgr: getVGuardInstance");
        }
    }

    fun onResume(activity: Activity) {
        if (vGuardMgr != null) {
            try {
                vGuardMgr!!.onResume(hook, activity)
            } catch (e: java.lang.Exception) {
                Log.e(TAG,"vGuardMgr.onPause throw exception causes: " + e.message)
            }
        }
    }

    fun onPause() {
        if (vGuardMgr != null) {
            try {
                vGuardMgr!!.onPause(hook)
            } catch (e: java.lang.Exception) {
                Log.e(TAG,"vGuardMgr.onPause throw exception causes: " + e.message)
            }
        }
    }

    fun resetThreatCount() {
        scanCompleteCount = 0;
        arrayThreat = mutableListOf<Map<String,String>>()
    }

    fun onDestroy() {
        Log.d(TAG, "destroying vGuardMgr")
        resetThreatCount()
        if (vGuardMgr != null) {
            try {
                vGuardMgr!!.destroy()
            } catch (e: java.lang.Exception) {
                Log.e(TAG,"vGuardMgr.onPause throw exception causes: " + e.message)
            }
            vGuardMgr = null
        }
    }



    open fun unregisterVguardReceivers(activity: Activity) {
        if (broadcastRvcr != null) {
            activity.unregisterReceiver(broadcastRvcr)
        }
        if(resetVOSTrustedStorageRvcr != null) {
            activity.unregisterReceiver(resetVOSTrustedStorageRvcr)
        }
    }

    open fun registerVguardReceivers(activity: Activity) {
        // for receiving notifications from VGuard
        broadcastRvcr = object : VGuardBroadcastReceiver(null) {
            override fun onReceive(context: Context, intent: Intent) {
                super.onReceive(context, intent)
                if (ACTION_FINISH == intent.action) {
                    sendVguardEvent("ACTION_FINISH", null)
                }
                else if (VOS_READY == intent.action) {
                    getVGuardInstance()
                    val TIUrl = ""; // ""https://..."
                    if(!TextUtils.isEmpty(TIUrl) && vGuardMgr != null) {
                        vGuardMgr?.setThreatIntelligenceServerURL(TIUrl)
                    }
                    val VOS_FIRMWARE_RETURN_CODE_KEY = "vkey.android.vguard.FIRMWARE_RETURN_CODE"
                    val firmwareReturnCode = intent.getLongExtra(VOS_FIRMWARE_RETURN_CODE_KEY, 0)
                    Log.d(TAG, "\nv-os return code: $firmwareReturnCode")
                    isVosReady = (firmwareReturnCode > 0);
                    resetThreatCount()
                    if (firmwareReturnCode == (-1019).toLong() /* Shadow hooking detected */) {
                        // TODO:
                        Log.d(TAG, "V-OS is locked because there is shadow hooking detected.");
                    } else if (firmwareReturnCode == (-1036).toLong() /* IOS_CODE_INJECTION_LOCK */) {
                        Log.d(TAG,"V-OS is locked cause IOS_CODE_INJECTION_LOCK");
                    } else if (firmwareReturnCode ==
                            (-1037).toLong() /* V-OS is locked because Java Frida hooking is detected */) {
                        Log.d(TAG,"V-OS is locked because Java Frida hooking is detected");
                        // TODO:
                    } else if (firmwareReturnCode == (-1046).toLong() /* Frida is detected */) {
                        // TODO:
                        Log.d(TAG,"V-OS is locked because Frida is detected");
                    } else if (firmwareReturnCode == (-1047).toLong() /* Magisk is detected */) {
                        // TODO:
                        Log.d(TAG,"V-OS is locked because Magisk is detected");
                    } else if (firmwareReturnCode == (-1039).toLong() /* Emulator is detecte */) {
                        // TODO:
                        Log.d(TAG,"V-OS is locked because Emulator is detected");
                    } else {
                        // TODO:
                    }
                    sendVguardEvent("VOS_READY", firmwareReturnCode)
                }
                else if (ACTION_SCAN_COMPLETE == intent.action) {
                    val arrayData = getArrayThreats(intent)
                    arrayThreat.addAll(arrayData);
                    scanCompleteCount++;
                    if(scanCompleteCount >= 2) {
                        sendVguardEvent("ACTION_SCAN_COMPLETE", arrayData)
                    }
                    /* val detectedThreats =
                            intent.getParcelableArrayListExtra<Parcelable>(VGuardBroadcastReceiver.SCAN_COMPLETE_RESULT) as java.util.ArrayList<Parcelable>?
                    for (info in detectedThreats!!) {
                        val threatInfo = info as BasicThreatInfo
                        val threatClass = threatInfo.threatClass;
                        if ("1000".equals(threatClass, true)) {
                            // TODO: THREAT_ROOT_JAILBREAK
                        } else if ("2000".equals(threatClass, true)) {
                            // TODO: THREAT_RATS
                        } else if ("3000".equals(threatClass, true)) {
                            // TODO: THREAT_APPLICATION_TAMPERING
                        } else if ("4000".equals(threatClass, true)) {
                            // TODO: THREAT_RUNTIME_TAMPERING
                        } else if ("5000".equals(threatClass, true)) {
                            // TODO: THREAT_LIBRARIES_TAMPERING
                        } else if ("6000".equals(threatClass, true)) {
                            // TODO: THREAT_MALWARE
                        }
                    } */
                }
                else if (VGUARD_OVERLAY_DETECTED == intent.action) {
                    sendVguardEvent("VGUARD_OVERLAY_DETECTED", true)
                }
                else if (VGUARD_OVERLAY_DETECTED_DISABLE == intent.action) {
                    sendVguardEvent("VGUARD_OVERLAY_DETECTED_DISABLE", true)
                }
                else  if (VGUARD_STOP_OVERLAY_SERVICE.equals(intent.getAction())) {
                    sendVguardEvent("VGUARD_STOP_OVERLAY_SERVICE", true)
                }
                else if (VGUARD_VIRTUAL_SPACE_DETECTED == intent.action) {
                    sendVguardEvent("VGUARD_VIRTUAL_SPACE_DETECTED", true)
                }
                else if (VGUARD_SCREEN_SHARING_DETECTED == intent.action) {
                    Log.d(TAG, "\n\nScreen Sharing Detected")
                    val sharingDisplays = intent.getStringExtra(VGUARD_SCREEN_SHARING_DISPLAY_NAMES)
                    val jsonArray = JSONArray(sharingDisplays)
                    sendVguardEvent("VGUARD_VIRTUAL_SPACE_DETECTED", jsonArray.toString())
                }
                else if (VGUARD_SIDELOADED_APP_WITH_ACCESSIBILITY_PERMISSION_DETECTED == intent.action) {
                    try {
                        val sideloadlist = intent.getStringExtra(VGUARD_SIDELOADED_RESULT)
                        if (!TextUtils.isEmpty(sideloadlist)) {
                            sendVguardEvent("VGUARD_SIDELOADED_APP_WITH_ACCESSIBILITY_PERMISSION_DETECTED", sideloadlist)
                        } else {
                            val builder = StringBuilder()
                            val packageID =
                                intent.getStringExtra("vkey.android.vguard.VGUARD_SIDELOADED_PACKAGE_ID")
                            val source =
                                intent.getStringExtra("vkey.android.vguard.VGUARD_SIDELOADED_SOURCE")
                            builder.append("\nPackageID: $packageID")
                            builder.append("\nSource Install: $source")
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                }
                else if (VGUARD_STATUS == intent.action) {
                    Log.d(TAG, "\nVGuard status ... ")

                    /*if (intent.hasExtra(VGUARD_HANDLE_THREAT_POLICY)) {
                        // // If the profile that you use has the vguardHandleThreatPolicy set to false
                        handleThreatPolicy(intent, "VGUARD_HANDLE_THREAT_POLICY")
                    }
                    else*/
                    if (intent.hasExtra(VGUARD_SSL_ERROR_DETECTED)) {
                        // If the profile that you use has the sslAlertBypass set to true,
                        handleSslErrorDetection(intent, "VGUARD_SSL_ERROR_DETECTED")
                    }
                    else {
                        val message = intent.getStringExtra(VGUARD_MESSAGE)
                        Log.d(TAG, "VGUARD_MESSAGE: $message")
                        /*if(message != null) {
                            sendVguardEvent("VGUARD_STATUS", message)
                        }*/
                    }
                }
            }
        }

        resetVOSTrustedStorageRvcr = object : VGuardBroadcastReceiver(null) {
            override fun onReceive(context: Context, intent: Intent) {
                super.onReceive(context, intent)
                val isResetVOSTrustedStorageSuccess = vGuardMgr!!.resetVOSTrustedStorage()
                sendVguardEvent("RESET_VOS_STORAGE", isResetVOSTrustedStorageSuccess)
            }
        }

        // register using LocalBroadcastManager only for keeping data within your app
        val localBroadcastMgr = LocalBroadcastManager.getInstance(activity)

        // necessary for vguard to finish activity safely
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.ACTION_FINISH))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.ACTION_SCAN_COMPLETE))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.VOS_READY))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.VGUARD_OVERLAY_DETECTED))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.VGUARD_STOP_OVERLAY_SERVICE))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.VGUARD_VIRTUAL_SPACE_DETECTED))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.VGUARD_SCREEN_SHARING_DETECTED))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.VGUARD_SIDELOADED_APP_WITH_ACCESSIBILITY_PERMISSION_DETECTED))
        localBroadcastMgr.registerReceiver(broadcastRvcr, IntentFilter(VGuardBroadcastReceiver.VGUARD_STATUS))

        val RESET_VOS_STORAGE = "vkey.android.vguard.resetVOSTrustedStorageRvcr"
        localBroadcastMgr.registerReceiver(resetVOSTrustedStorageRvcr, IntentFilter(RESET_VOS_STORAGE))
    }

    private fun getArrayThreats(intent: Intent): MutableList<Map<String,String>> {
        val detectedThreats =
            intent.getParcelableArrayListExtra<Parcelable>(VGuardBroadcastReceiver.SCAN_COMPLETE_RESULT) as ArrayList<Parcelable>?
        val builder = java.lang.StringBuilder()
        val arrayData = mutableListOf<Map<String,String>>()
        for (info in detectedThreats!!) {
            val threatInfo = info as BasicThreatInfo
            val infoMap = mutableMapOf<String, String>()
            infoMap["ThreatClass"] =  threatInfo.threatClass
            infoMap["ThreatInfo"] =  threatInfo.threatInfo
            infoMap["ThreatName"] =  threatInfo.threatName
            // infoMap["ThreatPackageID"] =  threatInfo.threatPackage
            arrayData.add(infoMap)
            // print log
            val infoStr = info.toString()
            builder.append(infoStr).append("\n")
        }
        Log.d(TAG, "\n\nDetected Threats: $builder")
        return arrayData
    }

    private fun handleSslErrorDetection(intent: Intent, eventName: String) {
        val sslErr = intent.getBooleanExtra(VGuardBroadcastReceiver.VGUARD_SSL_ERROR_DETECTED, false)
        Log.i(TAG, "${VGuardBroadcastReceiver.VGUARD_SSL_ERROR_DETECTED}:$sslErr".trimIndent())
        val mapData = mutableMapOf<String, Any>()
        mapData["VGUARD_SSL_ERROR_DETECTED"] = sslErr
        if (sslErr) {
            try {
                val jsonObject = JSONObject(intent.getStringExtra(VGuardBroadcastReceiver.VGUARD_MESSAGE))
                mapData["alertTitle"] =  jsonObject.optString(VGuardBroadcastReceiver.VGUARD_ALERT_TITLE)
                mapData["alertMessage"] =  jsonObject.optString(VGuardBroadcastReceiver.VGUARD_ALERT_MESSAGE)
                Log.i(TAG, jsonObject.toString())
            } catch (e: java.lang.Exception) {
            }
        }
        sendVguardEvent(eventName, mapData)
    }

    private fun handleThreatPolicy(intent: Intent, eventName: String) {
        val mapData = mutableMapOf<String, Any?>()
        val arrayThreats = getArrayThreats(intent)
        mapData["threats"] =  arrayThreats
        val highestResponse = intent.getIntExtra(VGuardBroadcastReceiver.VGUARD_HIGHEST_THREAT_POLICY, -1)
        mapData["highest_policy"] = highestResponse
        val alertTitle = intent.getStringExtra(VGuardBroadcastReceiver.VGUARD_ALERT_TITLE)
        mapData["alertTitle"] = alertTitle
        val alertMsg = intent.getStringExtra(VGuardBroadcastReceiver.VGUARD_ALERT_MESSAGE)
        mapData["alertMessage"] = alertMsg
        val disabledAppExpired = intent.getLongExtra(VGuardBroadcastReceiver.VGUARD_DISABLED_APP_EXPIRED, 0)
        mapData["disabledAppExpired"] = disabledAppExpired

        Log.i(TAG, "Vguard Status datas: ${mapData.toString()}")
        sendVguardEvent(eventName, mapData)
    }


}