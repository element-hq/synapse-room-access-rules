# Room Access rules

This module implements handling around the `im.vector.room.access_rules` state event. A specification for this event is described below.

## `im.vector.room.access_rules`

Restricts the access to a room based on the selected preset. Body:

```json
{
    "rule": "<rule>"
}
```

`<rule>` is either `restricted`, `unrestricted` or `direct`.

The implementation of the different presets lives in the
`synapse.third_party_rules.access_rules` module.

### `restricted` preset

Default preset for non-direct rooms (i.e. rooms not created with `"is_direct": true`).

Forbids any invite and membership update for users that belong to a server
that is in the blacklist provided by the module's configuration
(`domains_forbidden_when_restricted`). If the invite is a 3PID invite, queries
a custom `/_matrix/identity/api/v1/info` endpoint of the configured identity server to check if the invited email
address belongs to a blacklisted server.

### `unrestricted` preset

Doesn't apply any restriction on who can join the room.

Forbids any `m.room.power_levels` event that either:

* change the `users_default` power level to a non-0 value, or
* change the power level for a user from a blacklisted server (see details about the `restricted` preset) to a non-default value

### `direct` preset

Default preset for direct rooms (i.e. rooms created with `"is_direct": true`).

Only allow two members in the room by running the following algorithm for
each new event of type `m.room.member` or `m.room.third_party_invite` sent
into the room:

0. retrieve the list of memberships and 3PID invite tokens from the room's state, which in practice means retrieving the state key of every `m.room.member` or `m.room.third_party_invite` event present in the room's state (ignoring 3PID invite events with an empty content)

1. if the event is of type `m.room.third_party_invite`, and there are already events of the same type in the room's state, reject the new event if its state key doesn't match the state key of one of the existing events.

2. else, if there are already two members in the room:

    2.1. if the event is a 3PID invite, reject it

    2.2. if the event is a membership update, reject it if the target isn't one of the room's current members

3. else, if there is one membership event and one 3PID invite in the room's state:

    3.1. if the event is a membership event, reject it if it's not an invite exchanged from the 3PID invite that's in the room's state

    3.2. otherwise, reject the event

4. else, accept the event

Also forbids sending an event of the type `m.room.name`, `m.room.avatar_url`
or `m.room.topic` into the room.

### Interaction with `m.room.join_rules`

When the preset of the room is something other than `restricted`, changing the
room's join rule to `public` is forbidden. This is to ensure
users on blacklisted servers (see details about the `restricted` preset) can't
join a room unless they have been invited.

## Installation

TODO

## Config

Add the following to your Synapse config:

```yaml
modules:
  - module: room_access_rules.RoomAccessRules
    config:
        # List of domains (server names) that can't be invited to rooms if the
        # "restricted" rule is set. Defaults to an empty list.
        domains_forbidden_when_restricted: []
    
        # Identity server to use when checking the homeserver an email address belongs to
        # using the /info endpoint. Required.
        id_server: "vector.im"
```

## Development and Testing

This repository uses `tox` to run tests.

### Tests

This repository uses `unittest` to run the tests located in the `tests`
directory. They can be ran with `tox -e tests`.

### Making a release

```
git tag vX.Y
python3 setup.py sdist
twine upload dist/synapse-room-access-rules-X.Y.tar.gz
git push origin vX.Y
```