package com.glassfish.reforceapk;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.os.Bundle;
import android.util.ArrayMap;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import dalvik.system.DexClassLoader;

public class ReforceApplication extends Application {

    private static final String TAG = "ReforceApplication";

    private static final String appKey = "APPLICATION_CLASS_NAME";
    private String apkFileName;
    private String odexPath;
    private String libPath;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            File odex = this.getDir("payload_odex", MODE_PRIVATE);
            File libs = this.getDir("payload_lib", MODE_PRIVATE);
            odexPath = odex.getAbsolutePath();
            libPath = libs.getAbsolutePath();
            apkFileName = odex.getAbsolutePath() + "/payload.apk";
            File dexFile = new File(apkFileName);
            Log.i(TAG, "apk size: " + dexFile.length() + ", apk path: " + apkFileName);
            if (!dexFile.exists()) {
                dexFile.createNewFile();
                byte[] dexdata = this.readDexFileFromApk();
                this.splitPayloadFromDex(dexdata);
            }

            Object currentActivityThread = RefInvoke.invokeStaticMethod(
                    "android.app.ActivityThread",
                    "currentActivityThread",
                    new Class[] {},
                    new Object[]{});
            String packageName = this.getPackageName();
            ArrayMap mPackages = (ArrayMap) RefInvoke.getFieldOjbect(
                    "android.app.ActivityThread",
                    currentActivityThread,
                    "mPackages");

            WeakReference wr = (WeakReference) mPackages.get(packageName);
            DexClassLoader loader = new DexClassLoader(
                    apkFileName,
                    odexPath,
                    libPath,
                    (ClassLoader) RefInvoke.getFieldOjbect(
                            "android.app.LoadedApk",
                            wr.get(),
                            "mClassLoader"));
            RefInvoke.setFieldOjbect("android.app.LoadedApk",
                    "mClassLoader",
                    wr.get(),
                    loader);
            Log.i(TAG, "class loader: " + loader);
            try {
                Object activityObj = loader.loadClass("com.glassfish.reinforceapk.MainActivity");
                Log.i(TAG, "activityObj: " + activityObj);
            } catch (Exception ex) {
                Log.i(TAG, "activity: " + Log.getStackTraceString(ex));
            }
        } catch (Exception ex) {
            Log.i(TAG, "error: " + Log.getStackTraceString(ex));
            ex.printStackTrace();
        }
    }

    @Override
    public void onCreate() {
//        super.onCreate();
        Log.i(TAG, "ProxyApplication onCreate: ");
        String appClassName = null;
        try {
            ApplicationInfo ai = this.getPackageManager().getApplicationInfo(
                    this.getPackageName(), PackageManager.GET_META_DATA);
            Bundle bundle = ai.metaData;
            if (bundle != null && bundle.containsKey(appKey)) {
                appClassName = bundle.getString(appKey);
            } else {
                Log.i(TAG, "no application class name");
                return;
            }
        } catch (PackageManager.NameNotFoundException ex) {
            Log.i(TAG, "error: " + Log.getStackTraceString(ex));
            ex.printStackTrace();
        }

        Object currentActivityThread = RefInvoke.invokeStaticMethod(
                "android.app.ActivityThread",
                "currentActivityThread",
                new Class[]{},
                new Object[]{});
        Object mBoundApplication = RefInvoke.getFieldOjbect(
                "android.app.ActivityThread",
                currentActivityThread,
                "mBoundApplication");
        Object loadedApkInfo = RefInvoke.getFieldOjbect(
                "android.app.ActivityThread$AppBindData",
                mBoundApplication,
                "info");
        RefInvoke.setFieldOjbect("android.app.LoadedApk",
                "mApplication", loadedApkInfo, null);
        Object oldApplication = RefInvoke.getFieldOjbect("android.app.ActivityThread",
                currentActivityThread, "mInitialApplication");
        ArrayList<Application> mAllApplications = (ArrayList<Application>) RefInvoke.getFieldOjbect(
                "android.app.ActivityThread",
                currentActivityThread,
                "mAllApplications");

        mAllApplications.remove(oldApplication);

        ApplicationInfo appinfoInLoadedApk = (ApplicationInfo) RefInvoke.getFieldOjbect(
                "android.app.LoadedApk",
                loadedApkInfo,
                "mApplicationInfo");
        ApplicationInfo appinfoInAppBindData = (ApplicationInfo) RefInvoke.getFieldOjbect(
                "android.app.ActivityThread$AppBindData",
                mBoundApplication,
                "appInfo");
        appinfoInLoadedApk.className = appClassName;
        appinfoInAppBindData.className = appClassName;
        Application app = (Application) RefInvoke.invokeMethod("android.app.LoadedApk",
                "makeApplication",
                loadedApkInfo,
                new Class[]{boolean.class, Instrumentation.class},
                new Object[]{false, null});
        RefInvoke.setFieldOjbect("android.app.ActivityThread",
                "mInitialApplication",
                currentActivityThread,
                app);
        ArrayMap mProviderMap = (ArrayMap) RefInvoke.getFieldOjbect(
                "android.app.ActivityThread",
                currentActivityThread,
                "mProviderMap");
        Iterator it = mProviderMap.values().iterator();
        while (it.hasNext()) {
            Object providerClientRecord = it.next();
            Object localProvider = RefInvoke.getFieldOjbect(
                    "android.app.ActivityThread$ProviderClientRecord",
                    providerClientRecord, "mLocalProvider");
            RefInvoke.setFieldOjbect("android.content.ContentProvider",
                    "mContext", localProvider, app);
        }
        Log.i(TAG, "app: " + app);
        app.onCreate();
    }

    private void splitPayloadFromDex(byte[] apkData) throws IOException {
        int ablen = apkData.length;
        byte[] dexlen = new byte[4];
        System.arraycopy(apkData, ablen-4, dexlen, 0, 4);
        ByteArrayInputStream bais = new ByteArrayInputStream(dexlen);
        DataInputStream in = new DataInputStream(bais);
        int readInt = in.readInt();
        System.out.println(Integer.toHexString(readInt));

        byte[] newdex = new byte[readInt];
        System.arraycopy(apkData, ablen - 4 - readInt, newdex, 0, readInt);

        newdex = decrypt(newdex);
        File file = new File(apkFileName);
        try {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(newdex);
            fos.close();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        ZipInputStream zis = new ZipInputStream(
                new BufferedInputStream(new FileInputStream(file)));
        while (true) {
            ZipEntry entry = zis.getNextEntry();
            if (entry == null) {
                zis.close();
                break;
            }
            String name = entry.getName();
            if (name.startsWith("lib/") && name.endsWith(".so")) {
                File storeFile = new File(libPath + "/" +
                        name.substring(name.lastIndexOf("/")));
                storeFile.createNewFile();
                FileOutputStream fos = new FileOutputStream(storeFile);
                byte[] arrayOfByte = new byte[1024];
                while (true) {
                    int i = zis.read(arrayOfByte);
                    if (i == -1)
                        break;
                    fos.write(arrayOfByte);
                }
                fos.flush();
                fos.close();
            }
            zis.closeEntry();
        }
        zis.close();
    }

    private byte[] readDexFileFromApk() throws IOException {
        ByteArrayOutputStream dexOut = new ByteArrayOutputStream();
        ZipInputStream zis = new ZipInputStream(new BufferedInputStream(
                new FileInputStream(this.getApplicationInfo().sourceDir)));
        while (true) {
            ZipEntry zipEntry = zis.getNextEntry();
            if (zipEntry == null) {
                zis.close();
                break;
            }
            if (zipEntry.getName().equals("classes.dex")) {
                byte[] arrayOfByte = new byte[1024];
                while (true) {
                    int i = zis.read(arrayOfByte);
                    if (i== -1)
                        break;
                    dexOut.write(arrayOfByte, 0, i);
                }
            }
            zis.closeEntry();
        }
        zis.close();
        return dexOut.toByteArray();

    }

    private byte[] decrypt(byte[] srcData) {
        for (int i = 0; i < srcData.length; i++) {
            srcData[i] = (byte)(0xFF ^ srcData[i]);
        }
        return srcData;
    }

    protected AssetManager mAssetManager;
    protected Resources mResources;
    protected Resources.Theme mTheme;

    protected void loadResources(String dexPath) {
        try {
            AssetManager assetManager = AssetManager.class.newInstance();
            Method addAssetPath = assetManager.getClass().getMethod("addAssetPath", String.class);
            addAssetPath.invoke(assetManager, dexPath);
            mAssetManager = assetManager;
        } catch (Exception ex) {
            Log.i(TAG, "loadResources error: " + Log.getStackTraceString(ex));
            ex.printStackTrace();
        }
        Resources superRes = super.getResources();
        mResources = new Resources(mAssetManager, superRes.getDisplayMetrics(), superRes.getConfiguration());
        mTheme = mResources.newTheme();
        mTheme.setTo(super.getTheme());
    }

    @Override
    public AssetManager getAssets() {
        return mAssetManager == null ? super.getAssets() : mAssetManager;
    }

    @Override
    public Resources getResources() {
        return mResources == null ? super.getResources() : mResources;
    }

    @Override
    public Resources.Theme getTheme() {
        return mTheme == null ? super.getTheme() : mTheme;
    }
}
