/**
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import { useCallback, useEffect, useState } from 'react';
import { useHistory, useParams } from 'react-router';

import { useAsync } from 'shared/hooks/useAsync';

import cfg from 'teleport/config';
import useTeleport from 'teleport/useTeleport';

import { AuthConnectorEditorContent } from './AuthConnectorEditor';

const oidcTemplate = `kind: oidc
version: v3
metadata:
  name: connector-name
spec:
  issuer_url: https://accounts.google.com
  client_id: ""
  client_secret: ""
  redirect_url:
    - https://teleport.example.com/v1/webapi/oidc/callback
  claims_to_roles:
    - claim: email
      value: "*@example.com"
      roles:
        - access
  scope:
    - openid
    - email
    - profile
`;

const samlTemplate = `kind: saml
version: v2
metadata:
  name: connector-name
spec:
  display: "SAML"
  acs: https://teleport.example.com/v1/webapi/saml/acs
  entity_descriptor_url: ""
  attributes_to_roles:
    - name: groups
      value: "*"
      roles:
        - access
`;

/**
 * SSOConnectorInfo is the editor for OIDC and SAML connectors.
 */
export function SSOConnectorInfo({ isNew = false }) {
  const { connectorType, connectorName } = useParams<{
    connectorType: string;
    connectorName: string;
  }>();
  const ctx = useTeleport();
  const history = useHistory();

  const template = connectorType === 'saml' ? samlTemplate : oidcTemplate;
  const [content, setContent] = useState(template);
  const [initialContent, setInitialContent] = useState(template);

  const [fetchAttempt, fetchConnector] = useAsync(async () => {
    if (!isNew && connectorType === 'oidc') {
      const res = await ctx.resourceService.fetchOIDCConnector(connectorName);
      setContent(res.content);
      setInitialContent(res.content);
    }
    return;
  });

  const [saveAttempt, saveConnector] = useAsync(
    useCallback(async () => {
      if (connectorType === 'oidc') {
        if (isNew) {
          await ctx.resourceService
            .createOIDCConnector(content)
            .then(() => history.push(cfg.routes.sso));
        } else {
          await ctx.resourceService
            .updateOIDCConnector(connectorName, content)
            .then(() => history.push(cfg.routes.sso));
        }
      }
    }, [connectorName, connectorType, content, isNew, history, ctx.resourceService])
  );

  const isSaveDisabled =
    saveAttempt.status === 'processing' || content === initialContent;

  useEffect(() => {
    if (fetchAttempt.status !== 'success') {
      fetchConnector();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const typeName = connectorType?.toUpperCase() || 'SSO';
  const title = isNew
    ? `Creating new ${typeName} Auth Connector:`
    : `Editing ${typeName} Connector: ${connectorName}`;

  return (
    <AuthConnectorEditorContent
      title={title}
      content={content}
      backButtonRoute={cfg.routes.sso}
      isSaveDisabled={isSaveDisabled}
      saveAttempt={saveAttempt}
      fetchAttempt={fetchAttempt}
      onSave={saveConnector}
      onCancel={() => history.push(cfg.routes.sso)}
      setContent={setContent}
      isGithub={false}
    />
  );
}
