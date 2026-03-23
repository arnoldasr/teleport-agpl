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

import { Box, Card, Flex, H2, Subtitle2 } from 'design';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import cfg from 'teleport/config';

import { AccessRequestsPage } from '../AccessRequestsPage';

export function LockedAccessRequests() {
  if (cfg.entitlements.AccessRequests?.enabled) {
    return <AccessRequestsPage />;
  }

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
