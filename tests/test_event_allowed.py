# Copyright 2021 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import Optional

import aiounittest

from room_access_rules import ACCESS_RULES_TYPE, AccessRules, EventTypes, Membership
from tests import create_module, MockEvent


class SendEventTestCase(aiounittest.AsyncTestCase):
    def setUp(self) -> None:
        self.module = create_module(
            {"domains_forbidden_when_restricted": ["forbidden.com"]},
        )
        self.room_creator = "@mark:example.com"

        self.allowed_invitee = "@trina:allowed.com"
        self.other_allowed_invitee = "@alec:allowed.com"
        self.forbidden_invitee = "@jedidiah:forbidden.com"

        self.allowed_email = "trina@allowed.com"
        self.forbidden_email = "jedidiah@forbidden.com"

        self.direct_room = "!direct:example.com"
        self.direct_room_state = {
            (EventTypes.PowerLevels, ""): MockEvent(
                sender=self.room_creator,
                type=EventTypes.PowerLevels,
                state_key="",
                content=self.module._get_default_power_levels(self.room_creator),
                room_id=self.direct_room,
            ),
            (ACCESS_RULES_TYPE, ""): MockEvent(
                sender=self.room_creator,
                type=ACCESS_RULES_TYPE,
                state_key="",
                content={"rule": AccessRules.DIRECT},
                room_id=self.direct_room,
            ),
            (EventTypes.Member, self.room_creator): MockEvent(
                sender=self.room_creator,
                type=EventTypes.Member,
                state_key=self.room_creator,
                content={"membership": Membership.JOIN},
                room_id=self.direct_room,
            ),
            (EventTypes.Member, self.allowed_invitee): MockEvent(
                sender=self.room_creator,
                type=EventTypes.Member,
                state_key=self.allowed_invitee,
                content={"membership": Membership.INVITE},
                room_id=self.direct_room,
            ),
        }

        self.unrestricted_room = "!unrestricted:example.com"
        self.unrestricted_room_state = {
            (EventTypes.PowerLevels, ""): MockEvent(
                sender=self.room_creator,
                type=EventTypes.PowerLevels,
                state_key="",
                content=self.module._get_default_power_levels(self.room_creator),
                room_id=self.unrestricted_room,
            ),
            (ACCESS_RULES_TYPE, ""): MockEvent(
                sender=self.room_creator,
                type=ACCESS_RULES_TYPE,
                state_key="",
                content={"rule": AccessRules.UNRESTRICTED},
                room_id=self.unrestricted_room,
            ),
            (EventTypes.Member, self.room_creator): MockEvent(
                sender=self.room_creator,
                type=EventTypes.Member,
                state_key=self.room_creator,
                content={"membership": Membership.JOIN},
                room_id=self.unrestricted_room,
            ),
        }

        self.restricted_room = "!restricted:example.com"
        self.restricted_room_state = {
            (EventTypes.PowerLevels, ""): MockEvent(
                sender=self.room_creator,
                type=EventTypes.PowerLevels,
                state_key="",
                content=self.module._get_default_power_levels(self.room_creator),
                room_id=self.restricted_room,
            ),
            (ACCESS_RULES_TYPE, ""): MockEvent(
                sender=self.room_creator,
                type=ACCESS_RULES_TYPE,
                state_key="",
                content={"rule": AccessRules.RESTRICTED},
                room_id=self.restricted_room,
            ),
            (EventTypes.Member, self.room_creator): MockEvent(
                sender=self.room_creator,
                type=EventTypes.Member,
                state_key=self.room_creator,
                content={"membership": Membership.JOIN},
                room_id=self.restricted_room,
            ),
        }

    async def test_existing_room_can_change_power_levels(self):
        """Tests that a room created with default power levels can have their power levels
        dropped after room creation
        """
        pl_content = self.module._get_default_power_levels(self.room_creator)
        pl_content["invite"] = 0
        pl_content["state_default"] = 50
        pl_content["users_default"] = 1

        pl_event = MockEvent(
            sender=self.room_creator,
            type=EventTypes.PowerLevels,
            state_key="",
            content=pl_content,
        )

        allowed, _ = await self.module.check_event_allowed(
            event=pl_event, state_events=self.direct_room_state,
        )
        self.assertTrue(allowed)

        allowed, _ = await self.module.check_event_allowed(
            event=pl_event, state_events=self.unrestricted_room_state,
        )
        self.assertFalse(allowed)

    async def test_restricted(self):
        """Tests that in restricted mode we're unable to invite users from blacklisted
        servers but can invite other users.
        """
        # Tests that inviting an MXID from a forbidden HS isn't allowed.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_membership_event(
                self.room_creator,
                self.forbidden_invitee,
                Membership.INVITE,
                self.restricted_room,
            ),
            state_events=self.restricted_room_state,
        )

        self.assertFalse(allowed)

        # Tests that inviting an MXID from an allowed HS is allowed.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_membership_event(
                self.room_creator,
                self.allowed_invitee,
                Membership.INVITE,
                self.restricted_room,
            ),
            state_events=self.restricted_room_state,
        )

        self.assertTrue(allowed)

        # Tests that inviting an email address from a forbidden HS isn't allowed.
        # We test this through check_threepid_can_be_invited since this function will be
        # called before check_event_allowed, thus the check on whether the HS is allowed
        # or not happens here.
        allowed = await self.module.check_threepid_can_be_invited(
            medium="email",
            address=self.forbidden_email,
            state_events=self.restricted_room_state,
        )

        self.assertFalse(allowed)

        # Tests that inviting an email address from an allowed HS is allowed.
        allowed = await self.module.check_threepid_can_be_invited(
            medium="email",
            address=self.allowed_email,
            state_events=self.restricted_room_state,
        )

        self.assertTrue(allowed)

    async def test_direct(self):
        """Tests that, in direct mode, other users than the initial two can't be invited,
        but the following scenario works:
          * invited user joins the room
          * invited user leaves the room
          * room creator re-invites invited user

        Tests that a user from a HS that's in the list of forbidden domains (to use
        in restricted mode) can be invited.
        """
        # Test that a 3rd user can't be invited.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_membership_event(
                self.room_creator,
                self.other_allowed_invitee,
                Membership.INVITE,
                self.direct_room,
            ),
            state_events=self.direct_room_state,
        )
        self.assertFalse(allowed)

        # Test that the invited user can join.
        join_event = self._new_membership_event(
            self.allowed_invitee,
            self.allowed_invitee,
            Membership.JOIN,
            self.direct_room,
        )

        allowed, _ = await self.module.check_event_allowed(
            event=join_event, state_events=self.direct_room_state,
        )
        self.assertTrue(allowed)

        # Test that the invited user can leave.
        state_with_join = self.direct_room_state.copy()
        state_with_join[(EventTypes.Member, self.allowed_invitee)] = join_event

        leave_event = self._new_membership_event(
            self.allowed_invitee, self.allowed_invitee, "leave", self.direct_room,
        )

        allowed, _ = await self.module.check_event_allowed(
            event=leave_event, state_events=state_with_join,
        )
        self.assertTrue(allowed)

        # Test that the invited user can be re-invited to the room.
        state_with_leave = self.direct_room_state.copy()
        state_with_leave[(EventTypes.Member, self.allowed_invitee)] = leave_event

        invite_event = self._new_membership_event(
            self.room_creator, self.allowed_invitee, Membership.INVITE, self.direct_room,
        )

        allowed, _ = await self.module.check_event_allowed(
            event=invite_event, state_events=state_with_leave,
        )
        self.assertTrue(allowed)

        # Test that, if we're alone in the room and have always been the only member, we
        # can invite someone.
        state_with_no_invite = self.direct_room_state.copy()
        del state_with_no_invite[(EventTypes.Member, self.allowed_invitee)]

        # Test that can't send a 3PID invite to a room that already has two members.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_membership_event(
                self.room_creator,
                self.other_allowed_invitee,
                Membership.INVITE,
                self.direct_room,
            ),
            state_events=state_with_no_invite,
        )
        self.assertTrue(allowed)

        # Test that we can't send a 3PID invite to a room that already has a pending
        # invite.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_3pid_invite(self.room_creator, self.direct_room),
            state_events=state_with_join,
        )
        self.assertFalse(allowed)

        allowed, _ = await self.module.check_event_allowed(
            event=self._new_3pid_invite(self.room_creator, self.direct_room),
            state_events=self.direct_room_state,
        )
        self.assertFalse(allowed)

        # Test that we can send a 3PID invite to a room in which we've always been the
        # only member.
        state_with_3pid_invite = state_with_no_invite.copy()
        state_with_3pid_invite[(EventTypes.ThirdPartyInvite, "othertoken")] = (
            self._new_3pid_invite(self.room_creator, self.direct_room, token="othertoken")
        )

        # Test that we can't send a 3PID invite to a room in which there's already a 3PID
        # invite.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_3pid_invite(self.room_creator, self.direct_room),
            state_events=state_with_3pid_invite,
        )
        self.assertFalse(allowed)

    async def test_unrestricted(self):
        """Tests that, in unrestricted mode, we can invite whoever we want, but we can
        only change the power level of users that wouldn't be forbidden in restricted
        mode.
        """
        # We can invite
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_membership_event(
                self.room_creator,
                self.forbidden_invitee,
                Membership.INVITE,
                self.unrestricted_room,
            ),
            state_events=self.unrestricted_room_state,
        )
        self.assertTrue(allowed)

        allowed, _ = await self.module.check_event_allowed(
            event=self._new_membership_event(
                self.room_creator,
                self.allowed_invitee,
                Membership.INVITE,
                self.unrestricted_room,
            ),
            state_events=self.unrestricted_room_state,
        )
        self.assertTrue(allowed)

        # We can send a 3PID invite to an address that is mapped to a forbidden HS.
        self.assertTrue(
            await self.module.check_threepid_can_be_invited(
                medium="email",
                address=self.forbidden_email,
                state_events=self.unrestricted_room_state,
            )
        )

        # We can send a 3PID invite to an address that is mapped to an HS that's not
        # forbidden.
        self.assertTrue(
            await self.module.check_threepid_can_be_invited(
                medium="email",
                address=self.allowed_email,
                state_events=self.unrestricted_room_state,
            )
        )

        # We can send a power level event that doesn't redefine the default PL or set a
        # non-default PL for a user that would be forbidden in restricted mode.
        allowed, _ = await self.module.check_event_allowed(
            event=MockEvent(
                sender=self.room_creator,
                type=EventTypes.PowerLevels,
                state_key="",
                content={
                    "users": {self.room_creator: 100, self.allowed_invitee: 10},
                },
                room_id=self.unrestricted_room,
            ),
            state_events=self.unrestricted_room_state,
        )
        self.assertTrue(allowed)

        # We can't send a power level event that redefines the default PL and doesn't set
        # a non-default PL for a user that would be forbidden in restricted mode.
        allowed, _ = await self.module.check_event_allowed(
            event=MockEvent(
                sender=self.room_creator,
                type=EventTypes.PowerLevels,
                state_key="",
                content={
                    "users": {self.room_creator: 100, self.allowed_invitee: 10},
                    "users_default": 10,
                },
                room_id=self.unrestricted_room,
            ),
            state_events=self.unrestricted_room_state,
        )
        self.assertFalse(allowed)

        # We can't send a power level event that doesn't redefines the default PL but sets
        # a non-default PL for a user that would be forbidden in restricted mode.
        allowed, _ = await self.module.check_event_allowed(
            event=MockEvent(
                sender=self.room_creator,
                type=EventTypes.PowerLevels,
                state_key="",
                content={
                    "users": {self.room_creator: 100, self.forbidden_invitee: 10},
                    "users_default": 10,
                },
                room_id=self.unrestricted_room,
            ),
            state_events=self.unrestricted_room_state,
        )
        self.assertFalse(allowed)

    async def test_change_rules(self):
        """Tests that we can only change the current rule from restricted to
        unrestricted.
        """
        # We can't change the rule from restricted to direct.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_access_rules_event(
                self.room_creator, self.restricted_room, AccessRules.DIRECT,
            ),
            state_events=self.restricted_room_state
        )
        self.assertFalse(allowed)

        # We can change the rule from restricted to unrestricted.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_access_rules_event(
                self.room_creator, self.restricted_room, AccessRules.UNRESTRICTED,
            ),
            state_events=self.restricted_room_state
        )
        self.assertTrue(allowed)

        # We can't change the rule from unrestricted to restricted.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_access_rules_event(
                self.room_creator, self.unrestricted_room, AccessRules.RESTRICTED,
            ),
            state_events=self.unrestricted_room_state
        )
        self.assertFalse(allowed)

        # We can't change the rule from unrestricted to direct.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_access_rules_event(
                self.room_creator, self.unrestricted_room, AccessRules.DIRECT,
            ),
            state_events=self.unrestricted_room_state
        )
        self.assertFalse(allowed)

        # We can't change the rule from direct to restricted.
        allowed, _ = await self.module.check_event_allowed(
            event=self._new_access_rules_event(
                self.room_creator, self.direct_room, AccessRules.RESTRICTED,
            ),
            state_events=self.direct_room_state
        )
        self.assertFalse(allowed)

        allowed, _ = await self.module.check_event_allowed(
            event=self._new_access_rules_event(
                self.room_creator, self.direct_room, AccessRules.UNRESTRICTED,
            ),
            state_events=self.direct_room_state
        )
        self.assertFalse(allowed)

    async def test_change_room_avatar(self):
        """Tests that changing the room avatar is always allowed unless the room is a
        direct chat, in which case it's forbidden.
        """
        await self._test_allowed_except_direct(
            MockEvent(
                sender=self.room_creator,
                type=EventTypes.RoomAvatar,
                state_key="",
                content={
                    "info": {"h": 398, "mimetype": "image/jpeg", "size": 31037, "w": 394},
                    "url": "mxc://example.org/JWEIFJgwEIhweiWJE",
                },
            ),
        )

    async def test_change_room_name(self):
        """Tests that changing the room name is always allowed unless the room is a direct
        chat, in which case it's forbidden.
        """
        await self._test_allowed_except_direct(
            MockEvent(
                sender=self.room_creator,
                type=EventTypes.Name,
                state_key="",
                content={"name": "My super room"},
            ),
        )

    async def test_change_room_topic(self):
        """Tests that changing the room topic is always allowed unless the room is a
        direct chat, in which case it's forbidden.
        """
        await self._test_allowed_except_direct(
            MockEvent(
                sender=self.room_creator,
                type=EventTypes.Topic,
                state_key="",
                content={"topic": "Welcome to this room"},
            ),
        )

    async def test_revoke_3pid_invite_direct(self):
        """Tests that revoking a 3PID invite doesn't cause the room access rules module to
        confuse the revocation as a new 3PID invite.
        """
        invite_content = {
            "display_name": "ker...@exa...",
            "public_keys": [
                {
                    "key_validity_url": "https://validity_url",
                    "public_key": "ta8IQ0u1sp44HVpxYi7dFOdS/bfwDjcy4xLFlfY5KOA",
                },
                {
                    "key_validity_url": "https://validity_url",
                    "public_key": "4_9nzEeDwR5N9s51jPodBiLnqH43A2_g2InVT137t9I",
                },
            ],
            "key_validity_url": "https://validity_url",
            "public_key": "ta8IQ0u1sp44HVpxYi7dFOdS/bfwDjcy4xLFlfY5KOA",
        }

        # We need to consider a direct room with no invite here, so copy the state and
        # remove the invite event.
        state_events = self.direct_room_state.copy()
        del state_events[(EventTypes.Member, self.allowed_invitee)]

        # Check that the invite is allowed.
        invite_event = self._new_3pid_invite(
            self.room_creator, self.direct_room, invite_content,
        )

        allowed, _ = await self.module.check_event_allowed(
            event=invite_event,
            state_events=state_events,
        )

        self.assertTrue(allowed)

        # Add the invite into the room's state so we can revoke it.
        state_events[(EventTypes.ThirdPartyInvite, invite_event.state_key)] = invite_event

        # Check that the module understands a revocation of the invite as such, and not as
        # a new invite.
        invite_event = self._new_3pid_invite(
            self.room_creator, self.direct_room, {},
        )

        allowed, _ = await self.module.check_event_allowed(
            event=invite_event,
            state_events=state_events,
        )

        self.assertTrue(allowed)

        state_events[(EventTypes.ThirdPartyInvite, invite_event.state_key)] = invite_event

        # Check that the revoked invite is ignored when processing a new invite - if it
        # isn't then the module would reject it since it would think we're trying to send
        # a second invite in a DM, which is forbidden.
        invite_event = self._new_3pid_invite(
            self.room_creator, self.direct_room, invite_content, "someothertoken",
        )

        allowed, _ = await self.module.check_event_allowed(
            event=invite_event,
            state_events=state_events,
        )

        self.assertTrue(allowed)

    async def test_forbidden_users_join(self):
        """Tests that RoomAccessRules.check_event_allowed behaves accordingly.

        It tests that:
            * forbidden users cannot join restricted rooms.
            * forbidden users can only join unrestricted rooms if they have an invite.
        """
        allowed_join = self._new_membership_event(
            self.room_creator,
            self.allowed_invitee,
            Membership.JOIN,
        )

        forbidden_join = self._new_membership_event(
            self.room_creator,
            self.forbidden_invitee,
            Membership.JOIN,
        )

        state_events = self.restricted_room_state.copy()
        state_events[(EventTypes.Member, self.forbidden_invitee)] = (
            self._new_membership_event(
                self.room_creator,
                self.forbidden_invitee,
                Membership.INVITE,
            )
        )

        # Check that a forbidden user cannot join a restricted room, even with an invite.
        allowed, _ = await self.module.check_event_allowed(forbidden_join, state_events)
        self.assertFalse(allowed)

        # Check that an allowed user can join a restricted room, even without an invite.
        allowed, _ = await self.module.check_event_allowed(
            event=allowed_join, state_events=self.restricted_room_state,
        )
        self.assertTrue(allowed)

        # Check that a forbidden user cannot join an unrestricted room if they haven't
        # been invited into it.
        allowed, _ = await self.module.check_event_allowed(
            event=forbidden_join, state_events=self.unrestricted_room_state,
        )
        self.assertFalse(allowed)

        state_events = self.unrestricted_room_state.copy()
        state_events[(EventTypes.Member, self.forbidden_invitee)] = (
            self._new_membership_event(
                self.room_creator,
                self.forbidden_invitee,
                Membership.INVITE,
            )
        )

        # Check that a forbidden user can join an unrestricted room if they have been
        # invited into it.
        allowed, _ = await self.module.check_event_allowed(
            event=forbidden_join, state_events=state_events,
        )
        self.assertTrue(allowed)

    def _new_membership_event(
        self,
        src: str,
        target: str,
        membership: str,
        room_id: str = "!someroom",
    ) -> MockEvent:
        return MockEvent(
            sender=src,
            type=EventTypes.Member,
            state_key=target,
            content={"membership": membership},
            room_id=room_id,
        )

    def _new_3pid_invite(
        self,
        sender: str,
        room_id: str,
        content: Optional[dict] = None,
        token: str = "sometoken"
    ) -> MockEvent:
        return MockEvent(
            sender=sender,
            type=EventTypes.ThirdPartyInvite,
            content=content if content is not None else {"displayname": "foo"},
            state_key=token,
            room_id=room_id,
        )

    def _new_access_rules_event(
            self, sender: str, room_id: str, rule: str,
    ) -> MockEvent:
        return MockEvent(
            sender=sender,
            type=ACCESS_RULES_TYPE,
            state_key="",
            content={"rule": rule},
            room_id=room_id,
        )

    async def _test_allowed_except_direct(self, event: MockEvent):
        allowed, _ = await self.module.check_event_allowed(
            event=event,
            state_events=self.restricted_room_state,
        )
        self.assertTrue(allowed)

        allowed, _ = await self.module.check_event_allowed(
            event=event,
            state_events=self.unrestricted_room_state,
        )
        self.assertTrue(allowed)

        allowed, _ = await self.module.check_event_allowed(
            event=event,
            state_events=self.direct_room_state,
        )
        self.assertFalse(allowed)

