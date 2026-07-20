# ChatGPT public mobile-web causal memory

**Pack ID:** `17bda596a7530302a35eeed0336907dd96e35c1349f5694e246d1cc0b147e75b`  
**Source judgment:** `safal207/pythiaLabs` PR `#239`  
**Exact source head:** `cf15c07e7087f399db1b459c4850f5b4261c9b43`

## What CML remembers

The bounded public signed-out ChatGPT mobile-web audit produced a mostly positive result:

- public routes returned HTTP `200` across five controlled profiles;
- no horizontal overflow was detected;
- the composer remained visible at normal and compact height;
- critical mobile controls met the tested geometry threshold;
- the mobile login layout remained available;
- observed CLS was near zero;
- the mobile event endpoints returned successful HTTP responses.

It also remembers one P3 diagnostic:

- the public mobile login page repeatedly emitted an opaque first-party `console.error`;
- no visible login failure, uncaught page error, user impact or security impact was established.

## Rejected signals that must stay rejected

Future retrieval must not revive these as defects:

1. mobile event delivery failure — rejected because `200/204` responses arrived before the loading-aborted signal;
2. composer obstruction — rejected after screenshot review identified an ancestor container;
3. duplicate visible heading — rejected by the controlled browser matrix;
4. generic small-target count — insufficient for an accessibility failure because critical controls passed and link context was not adjudicated.

## Selected path

```text
scoped signed-out mobile baseline
→ public evidence cannot establish signed-in or native-app behaviour
→ run authorised authenticated mobile matrix
→ preserve scoped pass and one P3 diagnostic without overclaim
```

## Reuse rule

A future audit may retrieve this pack, but retrieval must not:

- change the P3 diagnostic into a login-failure claim;
- claim telemetry or user-data loss;
- claim a security vulnerability;
- generalise mobile web to Android or iOS native applications;
- generalise public signed-out evidence to long chat, streaming, attachments, history, Search, Projects, Work, settings, billing or offline recovery;
- treat a scoped pass as a universal product pass.

## Required next evidence

Before expanding the conclusion, run an authorised signed-in mobile-web matrix covering:

- long conversation and return-to-latest;
- streaming interruption and recovery;
- real virtual keyboard and browser chrome;
- attachments and image/file preview;
- sidebar history and deep links;
- offline/online recovery;
- TalkBack, zoom and external keyboard.

## Privacy and authority

The pack is public and contains no authenticated account, private chat, credential or user prompt data. It grants no execution, external-submission or merge authority.

Machine-readable pack: `examples/memory_packs/chatgpt_public_mobile_web_v1.json`.
