package com.glassfish.reinforceapk;

import android.app.Application;
import android.util.Log;

public class ReinforceApplication extends Application {

    private static final String TAG = "ReinforceApplication";
    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Source apk onCreate: " + this);
    }
}
