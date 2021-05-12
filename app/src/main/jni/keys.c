//
// Created by build3 on 2021/5/8.
//

#include <jni.h>
#include <android/log.h>
#include <string.h>

JNIEXPORT jstring JNICALL
Java_com_xie_jun_checksignaturedemo_MainActivity_nativeGetCertificateFingerprint(JNIEnv *env, jobject context) {
    // 获取 context 的类
    jclass context_clazz = (*env)->GetObjectClass(env, context);
    // 获取 getPackageManager 方法ID
    jmethodID methodID_getPackageManager = (*env)->GetMethodID(env,
            context_clazz, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    // 获取包管理器 PackageManager pm = context.getPackageManager();
    jobject packageManager = (*env)->CallObjectMethod(env, context, methodID_getPackageManager);

    jmethodID methodID_getPackageName = (*env)->GetMethodID(env,
            context_clazz, "getPackageName", "()Ljava/lang/String;");
    // 获取包名 String packageName = context.getPackageName();
    jstring packageName = (*env)->CallObjectMethod(env, context, methodID_getPackageName);
    // 打印包名
    const char *str = (*env)->GetStringUTFChars(env, packageName, 0);
    // Log.d("JNI", "packageName: " + packageName);
    __android_log_print(ANDROID_LOG_DEBUG, "JNI", "packageName: %s\n", str);

    jclass pm_clazz = (*env)->GetObjectClass(env, packageManager);
    jmethodID methodID_getPackageInfo = (*env)->GetMethodID(env,
            pm_clazz, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    int flags = 0x00000040;
    // PackageInfo packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
    jobject packageInfo = (*env)->CallObjectMethod(env,
            packageManager, methodID_getPackageInfo, packageName, flags);

    jclass packageInfo_clazz = (*env)->GetObjectClass(env, packageInfo);
    jfieldID fieldID_signatures = (*env)->GetFieldID(env, packageInfo_clazz,
            "signatures", "[Landroid/content/pm/Signature;");
    // 获取签名信息 Signature[] signatures = packageInfo.signatures;
    jobjectArray signatures = (*env)->GetObjectField(env, packageInfo, fieldID_signatures);
    // Signature signature = signatures[0];
    jobject signature = (*env)->GetObjectArrayElement(env, signatures, 0);

    jclass signature_clazz = (*env)->GetObjectClass(env, signature);
    jmethodID methodID_toByteArray = (*env)->GetMethodID(env, signature_clazz,
            "toByteArray", "()[B");
    // byte[] cert = signature.toByteArray();
    jbyteArray cert = (*env)->CallObjectMethod(env, signature, methodID_toByteArray);

    jclass x509_clazz = (*env)->FindClass(env, "javax/security/cert/X509Certificate");
    jmethodID methodID_getInstance = (*env)->GetStaticMethodID(env,
            x509_clazz, "getInstance", "([B)Ljavax/security/cert/X509Certificate;");
    // X509Certificate x509Certificate = X509Certificate.getInstance(cert);
    jobject x509 = (*env)->CallStaticObjectMethod(env, x509_clazz, methodID_getInstance, cert);

    jclass md_clazz = (*env)->FindClass(env, "java/security/MessageDigest");
    jmethodID methodID_md_getInstance = (*env)->GetStaticMethodID(env,
            md_clazz, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring algorithm = (*env)->NewStringUTF(env, "SHA1");
    // MessageDigest md = MessageDigest.getInstance(algorithm);
    jobject md = (*env)->CallStaticObjectMethod(env,
            md_clazz, methodID_md_getInstance, algorithm);

    jclass certificate_clazz = (*env)->GetSuperclass(env, x509_clazz);
    jmethodID methodID_getEncoded = (*env)->GetMethodID(env,
            certificate_clazz, "getEncoded", "()[B");
    // byte[] x509Encoded = x509.getEncoded();
    jbyteArray x509Encoded = (*env)->CallObjectMethod(env, x509, methodID_getEncoded);

    jmethodID methodID_digest = (*env)->GetMethodID(env, md_clazz, "digest", "([B)[B");
    // byte[] mdDigestBytes = md.digest(x509Encoded);
    jbyteArray mdDigestBytes = (*env)->CallObjectMethod(env, md, methodID_digest, x509Encoded);

    jclass mainActivity_clazz = (*env)->FindClass(env, "com/xie/jun/checksignaturedemo/MainActivity");
    jmethodID methodID_bytesToHexString = (*env)->GetStaticMethodID(env,
            mainActivity_clazz, "bytesToHexString", "([B)Ljava/lang/String;");
    // String hexString = bytesToHexString(mdDigestBytes)
    jstring hexString = (*env)->CallStaticObjectMethod(env,
            mainActivity_clazz, methodID_bytesToHexString, mdDigestBytes);
    const char *c_hexString = (*env)->GetStringUTFChars(env, hexString, 0);
    __android_log_print(ANDROID_LOG_DEBUG, "JNI", "fingerprint: %s\n", c_hexString);

    return hexString;
}

JNIEXPORT void JNICALL
Java_com_xie_jun_checksignaturedemo_MainActivity_nativeCheckFingerprint(JNIEnv *env, jobject thiz,
                                                                        jstring fingerprint) {

    const char *c_hexString = (*env)->GetStringUTFChars(env, fingerprint, 0);
    const char *realFingerprint = "19:D8:2F:44:94:B9:58:1E:67:E5:49:27:60:3C:B6:1C:3B:F0:59:C8";
    // 指纹匹配
    if (strcmp(c_hexString, realFingerprint) == 0) {
        __android_log_print(ANDROID_LOG_DEBUG, "JNI", "fingerprints match\n");
        return;
    }
    __android_log_print(ANDROID_LOG_DEBUG, "JNI", "fingerprints do not match\n");
    // 否则退出游戏
    jclass activity_clazz = (*env)->FindClass(env, "android/app/Activity");
    jmethodID methodID_finish = (*env)->GetMethodID(env, activity_clazz, "finish", "()V");
    // thiz.finish();
    (*env)->CallVoidMethod(env, thiz, methodID_finish);
}