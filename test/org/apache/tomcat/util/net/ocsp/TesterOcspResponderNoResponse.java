/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net.ocsp;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import javax.net.ServerSocketFactory;

import org.junit.Assert;

/*
 * An OCSP responder that swallows any input received and never responds. Use to test timeouts.
 */
public class TesterOcspResponderNoResponse {

    private static final int DEFAULT_PORT = 8888;

    private final int port;
    private ServerRunnable sr;

    public TesterOcspResponderNoResponse() {
        this(DEFAULT_PORT);
    }

    public TesterOcspResponderNoResponse(int port) {
        this.port = port;
    }

    public void start() {
        if (sr != null) {
            throw new IllegalStateException("Already started");
        }

        sr = new ServerRunnable(port);
        Thread t = new Thread(sr);
        t.start();

        Assert.assertTrue(sr.isAlive());
    }

    public void stop() {
        if (sr == null) {
            throw new IllegalStateException("Not started");
        }
        sr.stop();
    }


    private static class ServerRunnable implements Runnable {

        private final int port;
        private volatile boolean alive = true;
        private volatile ServerSocket serverSocket;

        ServerRunnable(int port) {
            this.port = port;
        }

        @Override
        public void run() {
            try {
                serverSocket = ServerSocketFactory.getDefault().createServerSocket();
                serverSocket.bind(new InetSocketAddress("localhost", port));

                while (alive) {
                    Socket socket = serverSocket.accept();
                    Thread t = new Thread(new SwallowRunnable(socket));
                    t.start();
                }
            } catch (IOException ioe) {
                // Don't print stack trace if we're shutting down (expected)
                if (alive) {
                    ioe.printStackTrace();
                }
            }
        }

        public void stop() {
            try {
                serverSocket.close();
                alive = false;
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }

        public boolean isAlive() {
            return alive;
        }
    }


    private static class SwallowRunnable implements Runnable {

        private final Socket socket;

        SwallowRunnable(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            byte[] buf = new byte[1024];
            try (InputStream os = socket.getInputStream()) {
                // Read until the client closes the socket
                while (os.read(buf) > 0) {
                    // Ignore any data read
                }
            } catch (IOException ignore) {
                // Ignore
            }
        }
    }
}
