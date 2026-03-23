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

import {
  Alert,
  Box,
  ButtonPrimary,
  ButtonSecondary,
  ButtonWarning,
  Flex,
  Indicator,
  Text,
} from 'design';
import Dialog, {
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from 'design/Dialog';
import { H2 } from 'design/Text';
import Table, { Cell } from 'design/DataTable';
import { useAsync } from 'shared/hooks/useAsync';

import {
  FeatureBox,
  FeatureHeader,
  FeatureHeaderTitle,
} from 'teleport/components/Layout';
import cfg from 'teleport/config';
import api from 'teleport/services/api';
import useTeleport from 'teleport/useTeleport';

type AccessRequest = {
  id: string;
  state: string;
  user: string;
  roles: string[];
  reason: string;
  created: string;
  expires: string;
  resolveReason?: string;
};

export function AccessRequestsPage() {
  const teleCtx = useTeleport();
  const currentUser = teleCtx.storeUser.getUsername();
  const canReview = teleCtx.storeUser.state?.acl?.accessRequests?.list || false;
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [reviewTarget, setReviewTarget] = useState<{
    id: string;
    action: 'approve' | 'deny';
  } | null>(null);
  const [reviewReason, setReviewReason] = useState('');
  const [error, setError] = useState('');

  const [fetchAttempt, fetchRequests] = useAsync(
    useCallback(async () => {
      const res = await api.get(cfg.getAccessRequestUrl());
      setRequests(res || []);
    }, [])
  );

  const [reviewAttempt, submitReview] = useAsync(async () => {
    if (!reviewTarget) return;
    const url = `${cfg.getAccessRequestUrl(reviewTarget.id)}/${reviewTarget.action}`;
    await api.put(url, { reason: reviewReason });
    setReviewTarget(null);
    setReviewReason('');
    await fetchRequests();
  });

  useEffect(() => {
    fetchRequests();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function formatDate(dateStr: string) {
    if (!dateStr) return '-';
    const d = new Date(dateStr);
    return d.toLocaleString();
  }

  function getStateColor(state: string) {
    switch (state) {
      case 'APPROVED':
        return 'success.main';
      case 'DENIED':
        return 'error.main';
      case 'PENDING':
        return 'warning.main';
      default:
        return 'text.primary';
    }
  }

  return (
    <FeatureBox>
      <FeatureHeader alignItems="center" justifyContent="space-between">
        <FeatureHeaderTitle>Access Requests</FeatureHeaderTitle>
        <Flex gap={2}>
          <ButtonSecondary size="medium" onClick={() => fetchRequests()}>
            Refresh
          </ButtonSecondary>
          <ButtonPrimary size="medium" onClick={() => setShowCreate(true)}>
            New Request
          </ButtonPrimary>
        </Flex>
      </FeatureHeader>

      {fetchAttempt.status === 'error' && (
        <Alert>{fetchAttempt.statusText}</Alert>
      )}
      {error && <Alert>{error}</Alert>}

      {fetchAttempt.status === 'processing' && (
        <Box textAlign="center" m={10}>
          <Indicator />
        </Box>
      )}

      {fetchAttempt.status === 'success' && (
        <>
          {requests.length === 0 ? (
            <Box p={4} textAlign="center">
              <H2 mb={2}>No access requests</H2>
              <Text color="text.slightlyMuted">
                Click "New Request" to create one, or use: tsh request create
                --roles=ROLE --reason="reason"
              </Text>
            </Box>
          ) : (
            <Table
              data={requests}
              columns={[
                {
                  key: 'id',
                  headerText: 'ID',
                  render: ({ id }) => (
                    <Cell style={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {id.substring(0, 8)}...
                    </Cell>
                  ),
                },
                {
                  key: 'state',
                  headerText: 'Status',
                  render: ({ state }) => (
                    <Cell>
                      <Text bold color={getStateColor(state)}>
                        {state}
                      </Text>
                    </Cell>
                  ),
                },
                {
                  key: 'user',
                  headerText: 'User',
                },
                {
                  key: 'roles',
                  headerText: 'Roles',
                  render: ({ roles }) => (
                    <Cell>{(roles || []).join(', ')}</Cell>
                  ),
                },
                {
                  key: 'reason',
                  headerText: 'Reason',
                  render: ({ reason }) => (
                    <Cell>{reason || '-'}</Cell>
                  ),
                },
                {
                  key: 'created',
                  headerText: 'Created',
                  render: ({ created }) => (
                    <Cell>{formatDate(created)}</Cell>
                  ),
                },
                {
                  key: 'actions',
                  headerText: 'Actions',
                  render: (req) => (
                    <Cell>
                      {req.state === 'PENDING' &&
                        canReview &&
                        req.user !== currentUser && (
                          <Flex gap={1}>
                            <ButtonPrimary
                              size="small"
                              onClick={() => {
                                setReviewTarget({
                                  id: req.id,
                                  action: 'approve',
                                });
                              }}
                            >
                              Approve
                            </ButtonPrimary>
                            <ButtonWarning
                              size="small"
                              onClick={() => {
                                setReviewTarget({
                                  id: req.id,
                                  action: 'deny',
                                });
                              }}
                            >
                              Deny
                            </ButtonWarning>
                          </Flex>
                        )}
                      {req.state === 'PENDING' &&
                        req.user === currentUser && (
                          <Text color="text.muted">Awaiting review</Text>
                        )}
                      {req.state !== 'PENDING' && (
                        <Text color="text.muted">
                          {req.resolveReason || '-'}
                        </Text>
                      )}
                    </Cell>
                  ),
                },
              ]}
              emptyText="No access requests"
            />
          )}
        </>
      )}

      {showCreate && (
        <CreateRequestDialog
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            fetchRequests();
          }}
          onError={(msg) => setError(msg)}
        />
      )}

      {reviewTarget && (
        <Dialog open={true} onClose={() => setReviewTarget(null)}>
          <DialogHeader>
            <DialogTitle>
              {reviewTarget.action === 'approve'
                ? 'Approve Request'
                : 'Deny Request'}
            </DialogTitle>
          </DialogHeader>
          <DialogContent>
            <Text mb={2}>Reason (optional):</Text>
            <input
              type="text"
              value={reviewReason}
              onChange={(e) => setReviewReason(e.target.value)}
              placeholder="Enter reason..."
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: '4px',
                border: '1px solid #ccc',
                fontSize: '14px',
              }}
            />
            {reviewAttempt.status === 'error' && (
              <Alert mt={2}>{reviewAttempt.statusText}</Alert>
            )}
          </DialogContent>
          <DialogFooter>
            <ButtonSecondary
              mr={2}
              onClick={() => setReviewTarget(null)}
            >
              Cancel
            </ButtonSecondary>
            {reviewTarget.action === 'approve' ? (
              <ButtonPrimary
                disabled={reviewAttempt.status === 'processing'}
                onClick={submitReview}
              >
                Approve
              </ButtonPrimary>
            ) : (
              <ButtonWarning
                disabled={reviewAttempt.status === 'processing'}
                onClick={submitReview}
              >
                Deny
              </ButtonWarning>
            )}
          </DialogFooter>
        </Dialog>
      )}
    </FeatureBox>
  );
}

function CreateRequestDialog({
  onClose,
  onCreated,
  onError,
}: {
  onClose: () => void;
  onCreated: () => void;
  onError: (msg: string) => void;
}) {
  const [roles, setRoles] = useState<string[]>([]);
  const [availableRoles, setAvailableRoles] = useState<string[]>([]);
  const [selectedRoles, setSelectedRoles] = useState<string[]>([]);
  const [reason, setReason] = useState('');

  const [fetchAttempt, fetchRoles] = useAsync(async () => {
    const res = await api.get(cfg.api.accessRequestRolesPath);
    setAvailableRoles(res.roles || []);
  });

  const [createAttempt, createRequest] = useAsync(async () => {
    if (selectedRoles.length === 0) {
      throw new Error('Select at least one role');
    }
    await api.post(cfg.getAccessRequestUrl(), {
      roles: selectedRoles,
      reason,
    });
    onCreated();
  });

  useEffect(() => {
    fetchRoles();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function toggleRole(role: string) {
    setSelectedRoles((prev) =>
      prev.includes(role) ? prev.filter((r) => r !== role) : [...prev, role]
    );
  }

  return (
    <Dialog open={true} onClose={onClose}>
      <DialogHeader>
        <DialogTitle>Create Access Request</DialogTitle>
      </DialogHeader>
      <DialogContent minWidth="450px">
        {fetchAttempt.status === 'processing' && <Indicator />}
        {fetchAttempt.status === 'error' && (
          <Alert mb={3}>{fetchAttempt.statusText}</Alert>
        )}
        {(fetchAttempt.status === 'success' || fetchAttempt.status === 'error') && (
          <>
            <Text mb={2} bold>
              Select Roles:
            </Text>
            <Box
              mb={3}
              p={2}
              css={`
                border: 1px solid ${(p: any) =>
                  p.theme.colors.interactive.tonal.neutral[1]};
                border-radius: 4px;
                max-height: 200px;
                overflow-y: auto;
              `}
            >
              {availableRoles.map((role) => (
                <Flex
                  key={role}
                  alignItems="center"
                  gap={2}
                  py={1}
                  css={`
                    cursor: pointer;
                    &:hover {
                      background: ${(p: any) =>
                        p.theme.colors.spotBackground[0]};
                    }
                  `}
                  onClick={() => toggleRole(role)}
                >
                  <input
                    type="checkbox"
                    checked={selectedRoles.includes(role)}
                    onChange={() => toggleRole(role)}
                  />
                  <Text>{role}</Text>
                </Flex>
              ))}
            </Box>
            <Text mb={2} bold>
              Reason:
            </Text>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why do you need access?"
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: '4px',
                border: '1px solid #ccc',
                fontSize: '14px',
              }}
            />
          </>
        )}
        {createAttempt.status === 'error' && (
          <Alert mt={2}>{createAttempt.statusText}</Alert>
        )}
      </DialogContent>
      <DialogFooter>
        <ButtonSecondary mr={2} onClick={onClose}>
          Cancel
        </ButtonSecondary>
        <ButtonPrimary
          disabled={
            createAttempt.status === 'processing' ||
            selectedRoles.length === 0
          }
          onClick={createRequest}
        >
          Submit Request
        </ButtonPrimary>
      </DialogFooter>
    </Dialog>
  );
}
