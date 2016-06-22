/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.as.domain.http.server;

import static org.jboss.as.domain.http.server.logging.HttpServerLogger.ROOT_LOGGER;
import static org.wildfly.security.auth.server.HttpAuthenticationFactory.getHostName;
import static org.xnio.Options.SSL_CLIENT_AUTH_MODE;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.SSLContext;

import org.jboss.as.controller.ControlledProcessStateService;
import org.jboss.as.controller.ModelController;
import org.jboss.as.domain.http.server.cors.CorsHttpHandler;
import org.jboss.as.domain.http.server.logging.HttpServerLogger;
import org.jboss.as.domain.http.server.security.AnonymousMechanism;
import org.jboss.as.domain.http.server.security.AuthenticationMechanismWrapper;
import org.jboss.as.domain.http.server.security.DmrFailureReadinessHandler;
import org.jboss.as.domain.http.server.security.ElytronSubjectDoAsHandler;
import org.jboss.as.domain.http.server.security.LogoutHandler;
import org.jboss.as.domain.http.server.security.RealmIdentityManager;
import org.jboss.as.domain.http.server.security.RedirectReadinessHandler;
import org.jboss.as.domain.http.server.security.ServerSubjectFactory;
import org.jboss.as.domain.http.server.security.SubjectDoAsHandler;
import org.jboss.as.domain.management.AuthMechanism;
import org.jboss.as.domain.management.SecurityRealm;
import org.jboss.modules.ModuleLoadException;
import org.wildfly.elytron.web.undertow.server.ElytronContextAssociationHandler;
import org.wildfly.elytron.web.undertow.server.ElytronRunAsHandler;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismInformation;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.xnio.BufferAllocator;
import org.xnio.ByteBufferSlicePool;
import org.xnio.ChannelListener;
import org.xnio.ChannelListeners;
import org.xnio.IoUtils;
import org.xnio.OptionMap;
import org.xnio.Options;
import org.xnio.SslClientAuthMode;
import org.xnio.StreamConnection;
import org.xnio.XnioWorker;
import org.xnio.channels.AcceptingChannel;
import org.xnio.conduits.StreamSinkConduit;
import org.xnio.ssl.SslConnection;
import org.xnio.ssl.XnioSsl;

import io.undertow.protocols.ssl.UndertowXnioSsl;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMode;
import io.undertow.security.handlers.AuthenticationCallHandler;
import io.undertow.security.handlers.AuthenticationConstraintHandler;
import io.undertow.security.handlers.AuthenticationMechanismsHandler;
import io.undertow.security.handlers.SecurityInitialHandler;
import io.undertow.security.handlers.SinglePortConfidentialityHandler;
import io.undertow.security.idm.DigestAlgorithm;
import io.undertow.security.impl.BasicAuthenticationMechanism;
import io.undertow.security.impl.CachedAuthenticatedSessionMechanism;
import io.undertow.security.impl.ClientCertAuthenticationMechanism;
import io.undertow.security.impl.DigestAuthenticationMechanism;
import io.undertow.security.impl.DigestQop;
import io.undertow.security.impl.GSSAPIAuthenticationMechanism;
import io.undertow.security.impl.SimpleNonceManager;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.server.handlers.CanonicalPathHandler;
import io.undertow.server.handlers.ChannelUpgradeHandler;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.cache.CacheHandler;
import io.undertow.server.handlers.cache.DirectBufferCache;
import io.undertow.server.handlers.error.SimpleErrorPageHandler;
import io.undertow.server.protocol.http.HttpOpenListener;
import io.undertow.util.Headers;

/**
 * The general HTTP server for handling management API requests.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ManagementHttpServer {

    private static final Map<Pattern, Charset> USER_AGENT_CHARSET_MAP = generateCharsetMap();

    private final HttpOpenListener openListener;
    private final InetSocketAddress httpAddress;
    private final InetSocketAddress secureAddress;
    private final XnioWorker worker;
    private volatile AcceptingChannel<StreamConnection> normalServer;
    private volatile AcceptingChannel<SslConnection> secureServer;
    private final SSLContext sslContext;
    private final SslClientAuthMode sslClientAuthMode;

    private ManagementHttpServer(HttpOpenListener openListener, InetSocketAddress httpAddress, InetSocketAddress secureAddress, SSLContext sslContext,
                                 SslClientAuthMode sslClientAuthMode, XnioWorker worker) {
        this.openListener = openListener;
        this.httpAddress = httpAddress;
        this.secureAddress = secureAddress;
        this.sslContext = sslContext;
        this.sslClientAuthMode = sslClientAuthMode;
        this.worker = worker;
    }

    public void start() {
        try {

            OptionMap.Builder serverOptionsBuilder = OptionMap.builder()
                    .set(Options.TCP_NODELAY, true)
                    .set(Options.REUSE_ADDRESSES, true);
            ChannelListener acceptListener = ChannelListeners.openListenerAdapter(openListener);
            if (httpAddress != null) {
                normalServer = worker.createStreamConnectionServer(httpAddress, acceptListener, serverOptionsBuilder.getMap());
                normalServer.resumeAccepts();
            }
            if (secureAddress != null) {
                if (sslClientAuthMode != null) {
                    serverOptionsBuilder.set(SSL_CLIENT_AUTH_MODE, sslClientAuthMode);
                }
                OptionMap secureOptions = serverOptionsBuilder.getMap();
                XnioSsl xnioSsl = new UndertowXnioSsl(worker.getXnio(), secureOptions, sslContext);
                secureServer = xnioSsl.createSslConnectionServer(worker, secureAddress, acceptListener, secureOptions);
                secureServer.resumeAccepts();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void stop() {
        IoUtils.safeClose(normalServer);
        IoUtils.safeClose(secureServer);
    }

    private static SSLContext getSSLContext(Builder builder) {
        if (builder.sslContext != null) {
            return builder.sslContext;
        } else if (builder.securityRealm != null) {
            return builder.securityRealm.getSSLContext();
        } else {
            throw ROOT_LOGGER.noRealmOrSSLContext();
        }
    }

    private static SslClientAuthMode getSslClientAuthMode(Builder builder) {
        if (builder.sslContext != null) {
            return null;
        } else if (builder.securityRealm != null) {
            Set<AuthMechanism> supportedMechanisms = builder.securityRealm.getSupportedAuthenticationMechanisms();
            if (supportedMechanisms.contains(AuthMechanism.CLIENT_CERT)) {
                if (supportedMechanisms.contains(AuthMechanism.DIGEST)
                        || supportedMechanisms.contains(AuthMechanism.PLAIN)) {
                    // Username / Password auth is possible so don't mandate a client certificate.
                    return SslClientAuthMode.REQUESTED;
                } else {
                    return SslClientAuthMode.REQUIRED;
                }
            }

            return null;
        } else {
            throw ROOT_LOGGER.noRealmOrSSLContext();
        }
    }

    private static ManagementHttpServer create(Builder builder) {
        SSLContext sslContext = null;
        SslClientAuthMode sslClientAuthMode = null;
        if (builder.secureBindAddress != null) {
            sslContext = getSSLContext(builder);
            if (sslContext == null) {
                throw ROOT_LOGGER.sslRequestedNoSslContext();
            }
            sslClientAuthMode = getSslClientAuthMode(builder);
        }

        HttpOpenListener openListener = new HttpOpenListener(new ByteBufferSlicePool(BufferAllocator.DIRECT_BYTE_BUFFER_ALLOCATOR, 4096, 10 * 4096));

        int secureRedirectPort = builder.secureBindAddress != null ? builder.secureBindAddress.getPort() : -1;
        // WFLY-2870 -- redirect not supported if bindAddress and secureBindAddress are using different InetAddress
        boolean redirectSupported = (builder.bindAddress == null || builder.secureBindAddress == null || builder.bindAddress.getAddress().equals(builder.secureBindAddress.getAddress()));
        if (!redirectSupported && secureRedirectPort > 0) {
            HttpServerLogger.ROOT_LOGGER.httpsRedirectNotSupported(builder.bindAddress.getAddress(), builder.secureBindAddress.getAddress());
            secureRedirectPort = -1;
        }

        setupOpenListener(openListener, secureRedirectPort, builder);
        return new ManagementHttpServer(openListener, builder.bindAddress, builder.secureBindAddress, sslContext, sslClientAuthMode, builder.worker);
    }

    private static void addRedirectRedinessHandler(PathHandler pathHandler, ResourceHandlerDefinition consoleHandler, Builder builder) {
        HttpHandler readinessHandler = new RedirectReadinessHandler(builder.securityRealm, consoleHandler.getHandler(), ErrorContextHandler.ERROR_CONTEXT);
        pathHandler.addPrefixPath(consoleHandler.getContext(), readinessHandler);
    }

    private static void addDmrRedinessHandler(PathHandler pathHandler, HttpHandler domainApiHandler, Builder builder) {
        HttpHandler readinessHandler = new DmrFailureReadinessHandler(builder.securityRealm, domainApiHandler, ErrorContextHandler.ERROR_CONTEXT);
        pathHandler.addPrefixPath(DomainApiCheckHandler.PATH, readinessHandler);
        pathHandler.addExactPath("management-upload", readinessHandler);
    }

    private static void addLogoutHandler(PathHandler pathHandler, Builder builder) {
        if (builder.securityRealm != null) {
            pathHandler.addPrefixPath(LogoutHandler.PATH, new LogoutHandler(builder.securityRealm.getName()));
        }
    }

    private static void setupOpenListener(HttpOpenListener listener, int secureRedirectPort, Builder builder) {
        CanonicalPathHandler canonicalPathHandler = new CanonicalPathHandler();

        ManagementHttpRequestHandler managementHttpRequestHandler = new ManagementHttpRequestHandler(builder.managementHttpRequestProcessor, canonicalPathHandler);
        CorsHttpHandler corsHandler = new CorsHttpHandler(managementHttpRequestHandler, builder.allowedOrigins);
        listener.setRootHandler(new UpgradeFixHandler(corsHandler));

        PathHandler pathHandler = new PathHandler();
        HttpHandler current = pathHandler;
        if (builder.upgradeHandler != null) {
            builder.upgradeHandler.setNonUpgradeHandler(current);
            current = builder.upgradeHandler;
        }

        if (secureRedirectPort > 0) {
            // Add handler for redirect from http to https if needed
            current = new SinglePortConfidentialityHandler(current, secureRedirectPort);
        }
        // caching handler, used for static resources
        current = new CacheHandler(new DirectBufferCache(1024, 1024 * 10, 1024 * 1000, BufferAllocator.BYTE_BUFFER_ALLOCATOR),
                current);
        current = new SimpleErrorPageHandler(current);

        canonicalPathHandler.setNext(current);

        ResourceHandlerDefinition consoleHandler = null;
        try {
            consoleHandler = builder.consoleMode.createConsoleHandler(builder.consoleSlot);
        } catch (ModuleLoadException e) {
            ROOT_LOGGER.consoleModuleNotFound(builder.consoleSlot == null ? "main" : builder.consoleSlot);
        }

        try {
            pathHandler.addPrefixPath(ErrorContextHandler.ERROR_CONTEXT, ErrorContextHandler.createErrorContext(builder.consoleSlot));
        } catch (ModuleLoadException e) {
            ROOT_LOGGER.errorContextModuleNotFound(builder.consoleSlot == null ? "main" : builder.consoleSlot);
        }

        ManagementRootConsoleRedirectHandler rootConsoleRedirectHandler = new ManagementRootConsoleRedirectHandler(consoleHandler);
        HttpHandler domainApiHandler = InExecutorHandler.wrap(
                builder.executor,
                associateIdentity(new DomainApiCheckHandler(builder.modelController, builder.controlledProcessStateService,
                        builder.allowedOrigins), builder)
        );
        pathHandler.addPrefixPath("/", rootConsoleRedirectHandler);
        if (consoleHandler != null) {
            addRedirectRedinessHandler(pathHandler, consoleHandler, builder);
        }

        domainApiHandler = secureDomainAccess(domainApiHandler, builder);
        addDmrRedinessHandler(pathHandler, domainApiHandler, builder);
        addLogoutHandler(pathHandler, builder);
    }

    private static HttpHandler associateIdentity(HttpHandler domainHandler, final Builder builder) {
        if (builder.httpAuthenticationFactory != null) {
            domainHandler = new ElytronSubjectDoAsHandler(domainHandler, builder.httpAuthenticationFactory.getSecurityDomain());
            domainHandler = new ElytronRunAsHandler(domainHandler);
        } else if (builder.securityRealm != null) {
            domainHandler = new SubjectDoAsHandler(domainHandler);
        }

        return new BlockingHandler(domainHandler);
    }

    private static HttpHandler secureDomainAccess(HttpHandler domainHandler, final Builder builder) {
        if (builder.httpAuthenticationFactory != null) {
            return secureDomainAccess(domainHandler, builder.httpAuthenticationFactory);
        } else if (builder.securityRealm != null) {
            return secureDomainAccess(domainHandler, builder.securityRealm);
        }

        return domainHandler;
    }

    private static HttpHandler secureDomainAccess(final HttpHandler domainHandler, final SecurityRealm securityRealm) {
        RealmIdentityManager rim = new RealmIdentityManager(securityRealm);
        List<AuthenticationMechanism> undertowMechanisms;
        if (securityRealm != null) {
            Set<AuthMechanism> mechanisms = securityRealm.getSupportedAuthenticationMechanisms();
            undertowMechanisms = new ArrayList<AuthenticationMechanism>(mechanisms.size());
            undertowMechanisms.add(wrap(new CachedAuthenticatedSessionMechanism(), null));
            for (AuthMechanism current : mechanisms) {
                switch (current) {
                    case KERBEROS:
                        undertowMechanisms.add(wrap(new GSSAPIAuthenticationMechanism(new ServerSubjectFactory(securityRealm,
                                rim)), current));
                        break;
                    case CLIENT_CERT:
                        undertowMechanisms.add(wrap(new ClientCertAuthenticationMechanism(), current));
                        break;
                    case DIGEST:
                        List<DigestAlgorithm> digestAlgorithms = Collections.singletonList(DigestAlgorithm.MD5);
                        List<DigestQop> digestQops = Collections.singletonList(DigestQop.AUTH);
                        undertowMechanisms.add(wrap(new DigestAuthenticationMechanism(digestAlgorithms, digestQops,
                                securityRealm.getName(), "/management", new SimpleNonceManager()), current));
                        break;
                    case PLAIN:
                        undertowMechanisms.add(wrap(new BasicAuthenticationMechanism(securityRealm.getName(), "BASIC", false, null, StandardCharsets.UTF_8, USER_AGENT_CHARSET_MAP), current));
                        break;
                    case LOCAL:
                        break;
                }
            }
        } else {
            undertowMechanisms = Collections.singletonList(wrap(new AnonymousMechanism(), null));
        }

        // If the only mechanism is the cached mechanism then no need to add these.
        HttpHandler current = domainHandler;
        current = new AuthenticationCallHandler(current);
        // Currently the security handlers are being added after a PATH handler so we know authentication is required by
        // this point.
        current = new AuthenticationConstraintHandler(current);
        current = new AuthenticationMechanismsHandler(current, undertowMechanisms);

        return new SecurityInitialHandler(AuthenticationMode.PRO_ACTIVE, rim, current);
    }

    private static Map<Pattern, Charset> generateCharsetMap() {
        final Map<Pattern, Charset> charsetMap = new HashMap<>();
        charsetMap.put(Pattern.compile("Mozilla/5\\.0 \\(.*\\) Gecko/.* Firefox/.*"), StandardCharsets.ISO_8859_1);
        charsetMap.put(Pattern.compile("(?!.*OPR)(?!.*Chrome)Mozilla/5\\.0 \\(.*\\).* Safari/.*"), StandardCharsets.ISO_8859_1);
        charsetMap.put(Pattern.compile("Mozilla/5\\.0 \\(.*; Trident/.*; rv:.*\\).*"), StandardCharsets.ISO_8859_1);
        charsetMap.put(Pattern.compile("Mozilla/5\\.0 \\(.* MSIE.* Trident/.*\\)"), StandardCharsets.ISO_8859_1);
        return Collections.unmodifiableMap(charsetMap);
    }

    private static AuthenticationMechanism wrap(final AuthenticationMechanism toWrap, final AuthMechanism mechanism) {
        return new AuthenticationMechanismWrapper(toWrap, mechanism);
    }

    private static HttpHandler secureDomainAccess(HttpHandler domainHandler, final HttpAuthenticationFactory httpAuthenticationFactory) {
        domainHandler = new AuthenticationCallHandler(domainHandler);
        domainHandler = new AuthenticationConstraintHandler(domainHandler);
        Function<HttpServerRequest, List<HttpServerAuthenticationMechanism>> mechanismSupplier = httpServerRequest -> {
            final String hostName = getHostName(httpServerRequest);
            final String protocol = httpServerRequest.getRequestURI().getScheme();
            return httpAuthenticationFactory.getMechanismNames().stream()
                    .map(s -> {
                        try {
                            // Now that we have the host name and protocol name, make sure the mechanism is actually available
                            MechanismInformation mechanismInformation = new MechanismInformation() {

                                @Override
                                public String getProtocol() {
                                    return protocol;
                                }

                                @Override
                                public String getMechanismType() {
                                    return "HTTP";
                                }

                                @Override
                                public String getMechanismName() {
                                    return s;
                                }

                                @Override
                                public String getHostName() {
                                    return hostName;
                                }
                            };
                            if (httpAuthenticationFactory.isMechAvailable(mechanismInformation)) {
                                return httpAuthenticationFactory.createMechanism(s);
                            } else {
                                return null;
                            }
                        } catch (Exception e) {
                            return null;
                        }
                    })
                    .filter(mech -> mech != null)
                    .collect(Collectors.toList());
        };
        domainHandler = ElytronContextAssociationHandler.builder()
                .setNext(domainHandler)
                .setMechanismSupplier(mechanismSupplier)
                .build();

        return domainHandler;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private boolean built = false;

        private InetSocketAddress bindAddress;
        private InetSocketAddress secureBindAddress;
        private ModelController modelController;
        private SecurityRealm securityRealm;
        private SSLContext sslContext;
        private HttpAuthenticationFactory httpAuthenticationFactory;
        private ControlledProcessStateService controlledProcessStateService;
        private ConsoleMode consoleMode;
        private String consoleSlot;
        private ChannelUpgradeHandler upgradeHandler;
        private ManagementHttpRequestProcessor managementHttpRequestProcessor;
        private Collection<String> allowedOrigins;
        private XnioWorker worker;
        private Executor executor;

        private Builder() {
        }

        public Builder setBindAddress(InetSocketAddress bindAddress) {
            assertNotBuilt();
            this.bindAddress = bindAddress;

            return this;
        }

        public Builder setSecureBindAddress(InetSocketAddress secureBindAddress) {
            assertNotBuilt();
            this.secureBindAddress = secureBindAddress;

            return this;
        }

        public Builder setModelController(ModelController modelController) {
            assertNotBuilt();
            this.modelController = modelController;

            return this;
        }

        public Builder setSecurityRealm(SecurityRealm securityRealm) {
            assertNotBuilt();
            this.securityRealm = securityRealm;

            return this;
        }

        public Builder setSSLContext(SSLContext sslContext) {
            assertNotBuilt();
            this.sslContext = sslContext;

            return this;
        }

        public Builder setHttpServerAuthentication(HttpAuthenticationFactory httpAuthenticationFactory) {
            assertNotBuilt();
            this.httpAuthenticationFactory = httpAuthenticationFactory;

            return this;
        }

        public Builder setControlledProcessStateService(ControlledProcessStateService controlledProcessStateService) {
            assertNotBuilt();
            this.controlledProcessStateService = controlledProcessStateService;

            return this;
        }

        public Builder setConsoleMode(ConsoleMode consoleMode) {
            assertNotBuilt();
            this.consoleMode = consoleMode;

            return this;
        }

        public Builder setConsoleSlot(String consoleSlot) {
            assertNotBuilt();
            this.consoleSlot = consoleSlot;

            return this;
        }

        public Builder setChannelUpgradeHandler(ChannelUpgradeHandler upgradeHandler) {
            assertNotBuilt();
            this.upgradeHandler = upgradeHandler;

            return this;
        }

        public Builder setManagementHttpRequestProcessor(ManagementHttpRequestProcessor managementHttpRequestProcessor) {
            assertNotBuilt();
            this.managementHttpRequestProcessor = managementHttpRequestProcessor;

            return this;
        }

        public Builder setAllowedOrigins(Collection<String> allowedOrigins) {
            assertNotBuilt();
            this.allowedOrigins = allowedOrigins;

            return this;
        }

        public Builder setWorker(XnioWorker worker) {
            assertNotBuilt();
            this.worker = worker;

            return this;
        }

        public Builder setExecutor(Executor executor) {
            assertNotBuilt();
            this.executor = executor;

            return this;
        }

        public ManagementHttpServer build() {
            assertNotBuilt();

            ManagementHttpServer managementHttpServer = create(this);
            built = true;

            return managementHttpServer;
        }

        private void assertNotBuilt() {
            if (built) {
                throw ROOT_LOGGER.managementHttpServerAlreadyBuild();
            }
        }

    }

    /**
     * Handler to work around a bug with old XNIO versions that did not handle
     * content-length for HTTP upgrade. This should be removed when it is no longer
     * nessesary to support WF 8.x clients.
     */
    private static class UpgradeFixHandler implements HttpHandler {

        final HttpHandler next;

        private UpgradeFixHandler(HttpHandler next) {
            this.next = next;
        }

        @Override
        public void handleRequest(HttpServerExchange exchange) throws Exception {
            if(exchange.getRequestHeaders().contains(Headers.UPGRADE)) {
                exchange.addResponseWrapper((factory, ex) -> {
                    StreamSinkConduit ret = factory.create();
                    if(exchange.getResponseHeaders().contains(Headers.UPGRADE)) {
                        exchange.getResponseHeaders().add(Headers.CONTENT_LENGTH, "0");
                    }
                    return ret;
                });
            }
            next.handleRequest(exchange);
        }
    }

}
