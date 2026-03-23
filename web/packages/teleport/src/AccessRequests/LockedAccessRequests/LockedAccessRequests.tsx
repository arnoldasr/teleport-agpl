/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

import React from 'react';

import { Box, Card, Flex, H2, Subtitle2, Text } from 'design';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import cfg from 'teleport/config';

export function LockedAccessRequests() {
  if (cfg.entitlements.AccessRequests?.enabled) {
    return <AccessRequestsInfo />;
  }

  return <AccessRequestsLocked />;
}

function AccessRequestsInfo() {
  return (
    <FeatureBox>
      <FeatureHeader alignItems="center" justifyContent="space-between">
        <FeatureHeaderTitle>Access Requests</FeatureHeaderTitle>
      </FeatureHeader>
      <Card p={4}>
        <H2 mb={3}>Access Requests are enabled</H2>
        <Subtitle2 mb={4} color="text.slightlyMuted">
          Use the CLI to create, review, and manage access requests.
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
            <strong># Create an access request</strong>
          </Text>
          <Text mb={3} ml={2}>
            tsh request create --roles=ROLE_NAME --reason="your reason"
          </Text>
          <Text mb={2}>
            <strong># List pending requests</strong>
          </Text>
          <Text mb={3} ml={2}>
            tsh request ls
          </Text>
          <Text mb={2}>
            <strong># Approve a request</strong>
          </Text>
          <Text mb={3} ml={2}>
            tsh request review --approve REQUEST_ID
          </Text>
          <Text mb={2}>
            <strong># Deny a request</strong>
          </Text>
          <Text ml={2}>tsh request review --deny REQUEST_ID</Text>
        </Box>
      </Card>
    </FeatureBox>
  );
}

function AccessRequestsLocked() {
  return (
    <FeatureBox>
      <FeatureHeader alignItems="center" justifyContent="space-between">
        <FeatureHeaderTitle>Access Requests</FeatureHeaderTitle>
      </FeatureHeader>
      <Card p={4}>
        <Flex flexDirection="column" alignItems="center" gap={3}>
          <H2>Access Requests are not enabled</H2>
          <Subtitle2 color="text.slightlyMuted">
            Enable the AccessRequests entitlement to use this feature.
          </Subtitle2>
        </Flex>
      </Card>
    </FeatureBox>
  );
}
