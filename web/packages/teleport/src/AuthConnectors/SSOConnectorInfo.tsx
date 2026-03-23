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

import { useHistory, useParams } from 'react-router';

import { Box, ButtonSecondary, Card, Flex, Text } from 'design';
import { H2, Subtitle2 } from 'design/Text';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import cfg from 'teleport/config';

export function SSOConnectorInfo() {
  const { connectorType, connectorName } = useParams<{
    connectorType: string;
    connectorName: string;
  }>();
  const history = useHistory();
  const typeName = connectorType?.toUpperCase() || 'SSO';

  return (
    <FeatureBox>
      <FeatureHeader alignItems="center" justifyContent="space-between">
        <FeatureHeaderTitle>
          {typeName} Connector: {connectorName}
        </FeatureHeaderTitle>
        <ButtonSecondary size="medium" onClick={() => history.push(cfg.routes.sso)}>
          Back
        </ButtonSecondary>
      </FeatureHeader>
      <Card p={4}>
        <H2 mb={3}>{connectorName}</H2>
        <Subtitle2 mb={4} color="text.slightlyMuted">
          Manage this {typeName} connector using the CLI.
        </Subtitle2>
        <Box
          p={3}
          css={`
            background: ${(p: any) => p.theme.colors.spotBackground[0]};
            border-radius: 8px;
            font-family: monospace;
          `}
        >
          <Text mb={2}>
            <strong># View connector configuration</strong>
          </Text>
          <Text mb={3} ml={2}>
            tctl get {connectorType}/{connectorName}
          </Text>
          <Text mb={2}>
            <strong># Edit connector (export, modify, apply)</strong>
          </Text>
          <Text mb={3} ml={2}>
            tctl get {connectorType}/{connectorName} {'>'} connector.yaml
          </Text>
          <Text mb={3} ml={2}>
            # edit connector.yaml
          </Text>
          <Text mb={3} ml={2}>
            tctl create -f connector.yaml
          </Text>
          <Text mb={2}>
            <strong># Delete connector</strong>
          </Text>
          <Text ml={2}>
            tctl rm {connectorType}/{connectorName}
          </Text>
        </Box>
      </Card>
    </FeatureBox>
  );
}
