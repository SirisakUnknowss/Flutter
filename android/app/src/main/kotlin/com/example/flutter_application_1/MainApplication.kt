package com.example.flutter_application_1

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import android.util.Log
import io.flutter.app.FlutterApplication



class MainApplication: FlutterApplication(), Application.ActivityLifecycleCallbacks {
    var vguardPlugin:VkVguardPlugin? = null
    override fun onCreate() {
        super.onCreate()
        appConext = this
        vguardPlugin = VkVguardPlugin.getInstance()
        registerActivityLifecycleCallbacks(this)
    }

    companion object {
        open var appConext: Context? = null
    }
    private var _currActivity = 0
    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
        _currActivity++
        if (vguardPlugin?.vGuardMgr == null && activity is MainActivity) {
            vguardPlugin?.registerVguardReceivers(activity)
              vguardPlugin?.setupVGuard(activity)
        }
    }

    override fun onActivityStarted(activity: Activity) {

    }

    override fun onActivityResumed(activity: Activity) {
        vguardPlugin?.onResume(activity)
    }

    override fun onActivityPaused(activity: Activity) {
        vguardPlugin?.onPause()
    }

    override fun onActivityStopped(activity: Activity) {
        _currActivity--
        Log.d("TAG", "onActivityDestroyed: $_currActivity")
        if (_currActivity <= 0) {
            vguardPlugin?.unregisterVguardReceivers(activity)
            vguardPlugin?.onDestroy()
        }
    }

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {

    }

    override fun onActivityDestroyed(activity: Activity) {

    }


}