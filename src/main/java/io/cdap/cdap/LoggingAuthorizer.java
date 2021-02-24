/*
 * Copyright © 2021 Cask Data, Inc.
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

import com.google.common.annotations.VisibleForTesting;
import io.cdap.cdap.proto.id.EntityId;
import io.cdap.cdap.proto.security.Action;
import io.cdap.cdap.proto.security.Principal;
import io.cdap.cdap.proto.security.Privilege;
import io.cdap.cdap.proto.security.Role;
import io.cdap.cdap.security.spi.authorization.AbstractAuthorizer;
import io.cdap.cdap.security.spi.authorization.AuthorizationContext;
import io.cdap.cdap.security.spi.authorization.Authorizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * This class implements {@link Authorizer} from CDAP and logs all authorization requests to INFO.
 */
public class LoggingAuthorizer extends AbstractAuthorizer {
  private static final Logger LOG = LoggerFactory.getLogger(LoggingAuthorizer.class);

  private AuthorizationContext context;

  @VisibleForTesting
  LoggingAuthorizer(AuthorizationContext context) {
    this.context = context;
  }

  @Override
  public void grant(io.cdap.cdap.proto.security.Authorizable authorizable, Principal principal, Set<Action> actions)
    throws Exception {
    throw new UnsupportedOperationException("Granting permissions is currently not supported.");
  }

  @Override
  public void revoke(io.cdap.cdap.proto.security.Authorizable authorizable, Principal principal, Set<Action> actions)
    throws Exception {
    throw new UnsupportedOperationException("Revoking permissions is currently not supported.");
  }

  @Override
  public void revoke(io.cdap.cdap.proto.security.Authorizable authorizable) throws Exception {
    throw new UnsupportedOperationException("Revoking permissions is currently not supported.");
  }

  @Override
  public Set<Privilege> listPrivileges(Principal principal) throws Exception {
    throw new UnsupportedOperationException("Listing permissions is currently not supported.");
  }

  @Override
  public void createRole(Role role) throws Exception {
    throw new UnsupportedOperationException("Creating roles is currently not supported.");
  }

  @Override
  public void dropRole(Role role) throws Exception {
    throw new UnsupportedOperationException("Dropping roles is currently not supported.");
  }

  @Override
  public void addRoleToPrincipal(Role role, Principal principal) throws Exception {
    throw new UnsupportedOperationException("Adding roles to principals is currently not supported.");
  }

  @Override
  public void removeRoleFromPrincipal(Role role, Principal principal) throws Exception {
    throw new UnsupportedOperationException("Removing roles from principals is currently not supported.");
  }

  @Override
  public Set<Role> listRoles(Principal principal) throws Exception {
    throw new UnsupportedOperationException("Listing roles for a principal is currently not supported.");
  }

  @Override
  public Set<Role> listAllRoles() throws Exception {
    throw new UnsupportedOperationException("Listing roles is currently not supported.");
  }

  @Override
  public void enforce(EntityId entityId, Principal principal, Set<Action> actions) throws Exception {
    LOG.info("enforce(entity: {}, principal: {}, credential: {}, actions: {})", entityId, principal,
             principal.getCredential(), actions.toString());
  }

  @Override
  public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {

    LOG.info("enforce(entities: {}, principal: {}, credential: {}, actions: VISIBLE)", entityIds, principal,
             principal.getCredential());
    return entityIds;
  }
}
