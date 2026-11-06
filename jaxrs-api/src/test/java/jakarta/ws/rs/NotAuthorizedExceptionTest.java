/*
 * Copyright (c) 2026 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package jakarta.ws.rs;

import static jakarta.ws.rs.core.HttpHeaders.WWW_AUTHENTICATE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;

/**
 * PoC / regression tests for {@link NotAuthorizedException#getChallenges()}.
 */
public class NotAuthorizedExceptionTest {

    @BeforeAll
    public static void setUp() {
        RuntimeDelegate.setInstance(mock(RuntimeDelegate.class, Mockito.RETURNS_DEEP_STUBS));
    }

    @AfterAll
    public static void tearDown() {
        RuntimeDelegate.setInstance(null);
    }

    @Test
    public void getChallengesFromResponseDoesNotExposeLiveHeaderList() {
        final List<Object> liveHeaderValues = new ArrayList<>();
        liveHeaderValues.add("Bearer realm=\"api\"");

        final MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        headers.put(WWW_AUTHENTICATE, liveHeaderValues);

        final Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(Response.Status.UNAUTHORIZED.getStatusCode());
        when(response.getStatusInfo()).thenReturn(Response.Status.UNAUTHORIZED);
        when(response.getHeaders()).thenReturn(headers);

        final NotAuthorizedException ex = new NotAuthorizedException(response);
        final List<Object> challenges = ex.getChallenges();

        assertEquals(1, challenges.size());
        assertThrows(UnsupportedOperationException.class, () -> challenges.add("Basic realm=\"evil\""));
        assertThrows(UnsupportedOperationException.class, challenges::clear);

        // Mutating the returned list must not alter response headers
        assertEquals(1, headers.get(WWW_AUTHENTICATE).size());
        assertTrue(headers.getFirst(WWW_AUTHENTICATE).toString().contains("Bearer"));
    }

    @Test
    public void getChallengesReturnsEmptyListWhenHeaderAbsent() {
        final MultivaluedMap<String, Object> headers = new MultivaluedHashMap<>();
        final Response response = mock(Response.class);
        when(response.getStatus()).thenReturn(Response.Status.UNAUTHORIZED.getStatusCode());
        when(response.getStatusInfo()).thenReturn(Response.Status.UNAUTHORIZED);
        when(response.getHeaders()).thenReturn(headers);

        final NotAuthorizedException ex = new NotAuthorizedException(response);
        assertTrue(ex.getChallenges().isEmpty());
        assertThrows(UnsupportedOperationException.class, () -> ex.getChallenges().add("x"));
    }
}
