/*
 * Copyright © 2020 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package io.cdap.cdap;

import io.cdap.cdap.proto.element.EntityType;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.mock;

public class LoggingAuthorizerTest {
  private class TestEntityId extends EntityId {
    private String entityName;
    private List<String> entityParts;

    public TestEntityId(String entityName, List<String> entityParts) {
      super(EntityType.NAMESPACE);
      this.entityName = entityName;
      this.entityParts = entityParts;
    }

    @Override
    public Iterable<String> toIdParts() {
      return entityParts;
    }

    @Override
    public String getEntityName() {
      return null;
    }
  }

  @Test
  public void testEnforceLogging() throws Exception {
    String entityName = "testNamespace";
    ArrayList<String> entityParts = new ArrayList<>();
    entityParts.add("namespace");
    entityParts.add("test");
    Principal principal = new Principal("test-principal", Principal.PrincipalType.USER, "creds");
    EntityId testEntity = new TestEntityId(entityName, entityParts);
    Set<Action> actions = new HashSet<>();
    actions.add(Action.ADMIN);

    AuthorizationContext mockContext = mock(AuthorizationContext.class);
    LoggingAuthorizer authorizer = new LoggingAuthorizer(mockContext);
    authorizer.enforce(testEntity, principal, actions);
  }

  @Test
  public void testIsVisibleLogging() throws Exception {
    String entityName = "testNamespace";
    ArrayList<String> entityParts = new ArrayList<>();
    entityParts.add("namespace");
    entityParts.add("test");
    Principal principal = new Principal("test-principal", Principal.PrincipalType.USER, "creds");
    TestEntityId testEntity = new TestEntityId(entityName, entityParts);
    Set<Action> actions = new HashSet<>();
    actions.add(Action.ADMIN);

    Set<TestEntityId> entityIds = new HashSet<>();
    entityIds.add(testEntity);

    AuthorizationContext mockContext = mock(AuthorizationContext.class);
    LoggingAuthorizer authorizer = new LoggingAuthorizer(mockContext);
    authorizer.isVisible(entityIds, principal);
  }
}
