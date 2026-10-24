cat << 'EOF' > make_tg_project.sh
#!/bin/bash
set -e

PROJECT_DIR="telegram-worker-apk-builder"
rm -rf "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR/.github/workflows"
mkdir -p "$PROJECT_DIR/patches"

# 1. ساخت کلاس پل ارتباطی SOCKS5 به WebSocket کلودفلر (بدون نیاز به هیچ کتابخانه خارجی، با جاوای خالص و SSL استاندارد اندروید)
cat << 'JAVA_EOF' > "$PROJECT_DIR/patches/WorkerBridgeServer.java"
package org.telegram.messenger;

import android.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class WorkerBridgeServer {
    private static volatile boolean isRunning = false;
    public static final int LOCAL_PORT = 10808;
    private static final String WORKER_HOST = "rough-voice-2425.yasharkia98.workers.dev";
    private static final int WORKER_PORT = 443;
    private static final String SECRET_KEY = "123456789";

    public static synchronized void startBridge() {
        if (isRunning) return;
        isRunning = true;

        Thread serverThread = new Thread(() -> {
            try {
                ServerSocket serverSocket = new ServerSocket(LOCAL_PORT, 100, InetAddress.getByName("127.0.0.1"));
                while (isRunning) {
                    Socket localSocket = serverSocket.accept();
                    localSocket.setTcpNoDelay(true);
                    handleClient(localSocket);
                }
            } catch (Exception e) {
                isRunning = false;
            }
        }, "CFWorkerBridgeMain");
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private static void handleClient(final Socket localSocket) {
        new Thread(() -> {
            SSLSocket wsSocket = null;
            try {
                InputStream in = localSocket.getInputStream();
                OutputStream out = localSocket.getOutputStream();

                // 1. SOCKS5 Greeting
                int ver = in.read();
                if (ver != 0x05) { localSocket.close(); return; }
                int nmethods = in.read();
                for (int i = 0; i < nmethods; i++) in.read();
                out.write(new byte[]{0x05, 0x00});
                out.flush();

                // 2. SOCKS5 Request (CMD, RSV, ATYP)
                int ver2 = in.read();
                int cmd = in.read();
                int rsv = in.read();
                int atyp = in.read();
                if (cmd != 0x01) { localSocket.close(); return; }

                String targetHost;
                if (atyp == 0x01) { // IPv4
                    byte[] ip = new byte[4];
                    readFully(in, ip);
                    targetHost = InetAddress.getByAddress(ip).getHostAddress();
                } else if (atyp == 0x03) { // Domain
                    int len = in.read();
                    byte[] dom = new byte[len];
                    readFully(in, dom);
                    targetHost = new String(dom, StandardCharsets.UTF_8);
                } else if (atyp == 0x04) { // IPv6
                    byte[] ip6 = new byte[16];
                    readFully(in, ip6);
                    targetHost = InetAddress.getByAddress(ip6).getHostAddress();
                } else {
                    localSocket.close();
                    return;
                }

                int portHigh = in.read();
                int portLow = in.read();
                int targetPort = ((portHigh & 0xFF) << 8) | (portLow & 0xFF);

                // تایید اتصال SOCKS5 به هسته C++ تلگرام
                out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
                out.flush();

                // 3. باز کردن اتصال TLS/WebSocket مستقیم به ورکر کلودفلر
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                wsSocket = (SSLSocket) factory.createSocket(WORKER_HOST, WORKER_PORT);
                wsSocket.setTcpNoDelay(true);
                wsSocket.startHandshake();

                InputStream wsIn = wsSocket.getInputStream();
                OutputStream wsOut = wsSocket.getOutputStream();

                byte[] keyBytes = new byte[16];
                new SecureRandom().nextBytes(keyBytes);
                String wsKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP);

                String path = "/?k=" + SECRET_KEY + "&host=" + targetHost + "&port=" + targetPort;
                String handshake = "GET " + path + " HTTP/1.1\r\n" +
                        "Host: " + WORKER_HOST + "\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Sec-WebSocket-Key: " + wsKey + "\r\n" +
                        "Sec-WebSocket-Version: 13\r\n\r\n";

                wsOut.write(handshake.getBytes(StandardCharsets.UTF_8));
                wsOut.flush();

                // خواندن هدرهای پاسخ HTTP 101
                StringBuilder headerSb = new StringBuilder();
                int b;
                while ((b = wsIn.read()) != -1) {
                    headerSb.append((char) b);
                    if (headerSb.length() >= 4 && headerSb.substring(headerSb.length() - 4).equals("\r\n\r\n")) {
                        break;
                    }
                }
                if (!headerSb.toString().contains("101")) {
                    wsSocket.close();
                    localSocket.close();
                    return;
                }

                final SSLSocket finalWsSocket = wsSocket;

                // ترد دریافت فریم‌های WebSocket از ورکر و نوشتن در سوکت تلگرام
                Thread downThread = new Thread(() -> {
                    try {
                        while (!localSocket.isClosed()) {
                            byte[] payload = readWsFrame(wsIn);
                            if (payload == null) break;
                            out.write(payload);
                            out.flush();
                        }
                    } catch (Exception ignored) {
                    } finally {
                        try { localSocket.close(); } catch (Exception ignored) {}
                        try { finalWsSocket.close(); } catch (Exception ignored) {}
                    }
                });
                downThread.setDaemon(true);
                downThread.start();

                // حلقه خواندن بایت‌های MTProto از تلگرام و ارسال در قالب فریم باینری WebSocket به ورکر
                byte[] buf = new byte[16384];
                int n;
                while ((n = in.read(buf)) != -1) {
                    writeWsFrame(wsOut, buf, n);
                }

            } catch (Exception ignored) {
            } finally {
                try { localSocket.close(); } catch (Exception ignored) {}
                if (wsSocket != null) {
                    try { wsSocket.close(); } catch (Exception ignored) {}
                }
            }
        }).start();
    }

    private static void readFully(InputStream in, byte[] buf) throws Exception {
        int offset = 0;
        while (offset < buf.length) {
            int r = in.read(buf, offset, buf.length - offset);
            if (r == -1) throw new Exception("EOF");
            offset += r;
        }
    }

    // ارسال فریم باینری Mask شده از کلاینت به سرور WebSocket (طبق استاندارد RFC 6455)
    private static synchronized void writeWsFrame(OutputStream out, byte[] data, int len) throws Exception {
        ByteArrayOutputStream frame = new ByteArrayOutputStream(len + 14);
        frame.write(0x82); // FIN + Binary Opcode (0x02)

        if (len <= 125) {
            frame.write(0x80 | len);
        } else if (len <= 65535) {
            frame.write(0x80 | 126);
            frame.write((len >> 8) & 0xFF);
            frame.write(len & 0xFF);
        } else {
            frame.write(0x80 | 127);
            for (int i = 7; i >= 0; i--) {
                frame.write((int) ((len >> (8 * i)) & 0xFF));
            }
        }

        byte[] mask = new byte[4];
        new SecureRandom().nextBytes(mask);
        frame.write(mask);

        byte[] masked = new byte[len];
        for (int i = 0; i < len; i++) {
            masked[i] = (byte) (data[i] ^ mask[i % 4]);
        }
        frame.write(masked);

        out.write(frame.toByteArray());
        out.flush();
    }

    // خواندن فریم WebSocket دریافتی از سرور کلودفلر
    private static byte[] readWsFrame(InputStream in) throws Exception {
        int b1 = in.read();
        if (b1 == -1) return null;
        int opcode = b1 & 0x0F;
        if (opcode == 0x08) return null; // Close frame

        int b2 = in.read();
        if (b2 == -1) return null;
        boolean isMasked = (b2 & 0x80) != 0;
        long len = b2 & 0x7F;

        if (len == 126) {
            len = ((in.read() & 0xFF) << 8) | (in.read() & 0xFF);
        } else if (len == 127) {
            len = 0;
            for (int i = 0; i < 8; i++) {
                len = (len << 8) | (in.read() & 0xFF);
            }
        }

        byte[] mask = null;
        if (isMasked) {
            mask = new byte[4];
            readFully(in, mask);
        }

        byte[] payload = new byte[(int) len];
        readFully(in, payload);

        if (isMasked && mask != null) {
            for (int i = 0; i < payload.length; i++) {
                payload[i] ^= mask[i % 4];
            }
        }
        return payload;
    }
}
JAVA_EOF

# 2. ساخت اسکریپت پایتون برای تزریق خودکار کد به ApplicationLoader.java در سورس تلگرام
cat << 'PY_EOF' > "$PROJECT_DIR/patches/inject_patch.py"
import sys
import os

app_loader_path = "Telegram/TMessagesProj/src/main/java/org/telegram/messenger/ApplicationLoader.java"

if not os.path.exists(app_loader_path):
    print("Error: ApplicationLoader.java not found!")
    sys.exit(1)

with open(app_loader_path, "r", encoding="utf-8") as f:
    content = f.read()

hook_code = """
        // --- AUTO START CLOUDFLARE WORKER BRIDGE ---
        try {
            WorkerBridgeServer.startBridge();
            android.content.SharedPreferences mainPrefs = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", android.content.Context.MODE_PRIVATE);
            mainPrefs.edit()
                .putString("proxy_ip", "127.0.0.1")
                .putInt("proxy_port", 10808)
                .putString("proxy_user", "")
                .putString("proxy_pass", "")
                .putString("proxy_secret", "")
                .putBoolean("proxy_enabled", true)
                .apply();
            org.telegram.tgnet.ConnectionsManager.setProxySettings(true, "127.0.0.1", 10808, "", "", "");
        } catch (Exception ignored) {}
        // -------------------------------------------
"""

target_marker = "super.onCreate();"
if target_marker in content:
    content = content.replace(target_marker, target_marker + "\n" + hook_code, 1)
    with open(app_loader_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("Successfully injected WorkerBridgeServer into ApplicationLoader.java")
else:
    print("Could not find super.onCreate() in ApplicationLoader.java")
    sys.exit(1)
PY_EOF

# 3. ساخت ورک‌فلو GitHub Actions برای کامپایل کامل سورس تلگرام
cat << 'YAML_EOF' > "$PROJECT_DIR/.github/workflows/build-telegram.yml"
name: Build Custom Worker Telegram APK

on:
  workflow_dispatch:
  push:
    branches: [ main, master ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Maximize Build Space
        run: |
          sudo rm -rf /usr/share/dotnet
          sudo rm -rf /opt/ghc
          sudo rm -rf "/usr/local/share/boost"
          sudo rm -rf "$AGENT_TOOLSDIRECTORY"
          df -h

      - name: Checkout Builder Repo
        uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '17'

      - name: Setup Android SDK & NDK
        uses: android-actions/setup-android@v3

      - name: Install NDK & CMake required by Telegram
        run: |
          yes | sdkmanager --licenses || true
          sdkmanager "ndk;21.4.7075529" "cmake;3.18.1" "platforms;android-34" "build-tools;34.0.0"

      - name: Clone Official Telegram Android Source (Forkgram Clean Build Tree)
        run: |
          git clone --depth=1 --recursive https://github.com/Forkgram/TelegramAndroid.git Telegram

      - name: Inject Cloudflare Worker Bridge into Telegram Source
        run: |
          cp patches/WorkerBridgeServer.java Telegram/TMessagesProj/src/main/java/org/telegram/messenger/WorkerBridgeServer.java
          python3 patches/inject_patch.py

      - name: Prepare Dummy google-services.json & Signing Keystore
        run: |
          cd Telegram
          keytool -genkey -v -keystore TMessagesProj/config/release.keystore -alias release -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android -dname "CN=TelegramWorker, OU=Dev, O=Worker, L=World, S=World, C=US" || true

      - name: Build Telegram APK
        env:
          ANDROID_HOME: ${{ env.ANDROID_SDK_ROOT }}
        run: |
          cd Telegram
          chmod +x gradlew
          ./gradlew assembleAfatDebug --no-daemon --max-workers=2

      - name: Upload Compiled Telegram APK
        uses: actions/upload-artifact@v4
        with:
          name: Telegram-Worker-Edition-APK
          path: Telegram/TMessagesProj/build/outputs/apk/**/*.apk
YAML_EOF

zip -r "${PROJECT_DIR}.zip" "$PROJECT_DIR"
echo "✅ فایل ${PROJECT_DIR}.zip با موفقیت ساخته شد!"
EOF
chmod +x make_tg_project.sh
./make_tg_project.sh