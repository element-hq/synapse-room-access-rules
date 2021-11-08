# -*- coding: utf-8 -*-
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
from unittest.mock import Mock

from synapse.module_api import ModuleApi, UserID

from room_access_rules import RoomAccessRules


class MockHttpClient:
    async def get_json(self, uri, args):
        return {"hs": args["address"].split('@')[1]}


class MockPublicRoomListManager:
    _public_room = "!public:example.com"

    async def room_is_in_public_room_list(self, room_id: str) -> bool:
        return room_id == self._public_room


class MockRequester:

    def __init__(self, user_id: str):
        self.user = UserID.from_string(user_id)


def create_module(config_override={}) -> RoomAccessRules:
    # Create a mock based on the ModuleApi spec, but override some mocked functions
    # because some capabilities are needed for running the tests.
    module_api = Mock(spec=ModuleApi)
    module_api.http_client = MockHttpClient()
    module_api.public_room_list_manager = MockPublicRoomListManager()

    config_override["id_server"] = "example.com"

    config = RoomAccessRules.parse_config(config_override)

    return RoomAccessRules(config, module_api)