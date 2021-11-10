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

from room_access_rules import ACCESS_RULES_TYPE, AccessRules
from tests import create_module, PUBLIC_ROOM_ID, new_access_rules_event


class RoomVisibilityTestCase(aiounittest.AsyncTestCase):
    def setUp(self) -> None:
        self.module = create_module()
        self.user_id = "@someuser:example.com"

    async def test_change_rules_when_published(self):
        """Tests that the rule of a room cannot be set to something other than
        'restricted' when the room is published in the room directory.
        """
        state = {
            (ACCESS_RULES_TYPE, ""): new_access_rules_event(
                self.user_id, PUBLIC_ROOM_ID, AccessRules.RESTRICTED,
            )
        }

        # Check that we can't change the rule to 'unrestricted'.
        allowed, _ = await self.module.check_event_allowed(
            event=new_access_rules_event(
                self.user_id, PUBLIC_ROOM_ID, AccessRules.UNRESTRICTED,
            ),
            state_events=state,
        )

        self.assertFalse(allowed)

        # Check that we can't change the rule to 'direct'.
        allowed, _ = await self.module.check_event_allowed(
            event=new_access_rules_event(
                self.user_id, PUBLIC_ROOM_ID, AccessRules.DIRECT,
            ),
            state_events=state,
        )

        self.assertFalse(allowed)

    async def test_change_visibility_direct(self):
        """Tests that direct rooms can't be published to the room directory."""
        await self._test_change_visibility_to_public(
            rule=AccessRules.DIRECT, expect_allowed=False,
        )

    async def test_change_visibility_restricted(self):
        """Tests that restricted rooms can be published to the room directory."""
        await self._test_change_visibility_to_public(
            rule=AccessRules.RESTRICTED, expect_allowed=True,
        )

    async def test_change_visibility_unrestricted(self):
        """Tests that unrestricted rooms can't be published to the room directory."""
        await self._test_change_visibility_to_public(
            rule=AccessRules.UNRESTRICTED, expect_allowed=False,
        )

    async def test_change_visibility_no_rule(self):
        """Tests that rooms without a rule can be published to the room directory, since
         their rooms are assumed to be 'restricted'.
         """
        await self._test_change_visibility_to_public(
            rule=None, expect_allowed=True,
        )

    async def _test_change_visibility_to_public(
        self, rule: Optional[str], expect_allowed: bool,
    ):
        """Test if a room with the given rule can be published to the server's room
        directory.

        Args:
            rule: The rule for the room, or None if the room should have no rule in its
                state.
            expect_allowed: Whether the visibility change is expected to be allowed.
        """
        room_id = "!someroom"

        state = {}
        if rule is not None:
            state[(ACCESS_RULES_TYPE, "")] = new_access_rules_event(
                self.user_id, room_id, rule,
            )

        self.assertEqual(
            await self.module.check_visibility_can_be_modified(room_id, state, "public"),
            expect_allowed,
        )
