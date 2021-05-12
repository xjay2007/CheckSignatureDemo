package com.xie.jun.checksignaturedemo;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("keys");
    }

    private static final String TAG = MainActivity.class.getSimpleName();

    private native String nativeGetCertificateFingerprint();
    private native void nativeCheckFingerprint(String fingerprint);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        TextView tv = findViewById(R.id.sample_text);
//        tv.setText(getCertificateFingerprint(this, "MD5"));

        String fingerprint = nativeGetCertificateFingerprint();
        Log.d(TAG, "fingerprint: " + getCertificateFingerprint(this, "SHA1"));
        Log.d(TAG, "native fingerprint: " + fingerprint);
//        if (!fingerprint.equals("19:D8:2F:44:94:B9:58:1E:67:E5:49:27:60:3C:B6:1C:3B:F0:59:C8")) {
//            finish();
//        }
        nativeCheckFingerprint(nativeGetCertificateFingerprint());
    }

    @Override
    protected void onDestroy() {
        Log.d(TAG, "onDestroy");
        super.onDestroy();
    }

    /**
     * 获取证书指纹
     * @param context 上下文
     * @param algorithm 算法
     * @return
     */
    private static String getCertificateFingerprint(Context context, String algorithm) {
        // 获取包管理器
        PackageManager pm = context.getPackageManager();
        // 获取包名
        String packageName = context.getPackageName();

        try {
            PackageInfo packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            // 获取签名信息
            Signature[] signatures = packageInfo.signatures;
            byte[] cert = signatures[0].toByteArray();
            // 获取X.509证书
            X509Certificate x509Certificate = X509Certificate.getInstance(cert);
            // 选择讯息摘要算法，例如：MD5，SHA1，SHA256
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] bytes = md.digest(x509Certificate.getEncoded());
            // 转换为 16 进制格式字符串
            return bytesToHexString(bytes);
        } catch (PackageManager.NameNotFoundException | CertificateException |
                NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 转换为 16 进制格式
     * @param bytes
     * @return
     */
    public static String bytesToHexString(byte[] bytes) {
        int length = bytes.length;
        Formatter formatter = new Formatter();

        for (int i = 0; i < length; ++i) {
            formatter.format("%02X", bytes[i]);
            if (i < length - 1) {
                formatter.format("%s", ":");
            }
        }
        String result = formatter.toString();
        formatter.close();

        return result;
    }
}