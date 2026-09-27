import assert from 'node:assert/strict';
import test from 'node:test';
import { parseUploadedFile } from '../src/utils/pcapParser';
import { addSecurityAssociationEvidence } from '../src/analysis/evidence';
import { classifyEspTraffic } from '../src/utils/aiClassifier';

function writeU16(target: Uint8Array, offset: number, value: number): void {
  target[offset] = value >> 8;
  target[offset + 1] = value & 0xff;
}

function writeU32(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

function makeIkeV2Pcap(): File {
  const packetLength = 14 + 20 + 8 + 28;
  const bytes = new Uint8Array(24 + 16 + packetLength);
  writeU32(bytes, 0, 0xa1b2c3d4);
  writeU16(bytes, 4, 2);
  writeU16(bytes, 6, 4);
  writeU32(bytes, 16, 65535);
  writeU32(bytes, 20, 1);
  writeU32(bytes, 24, 1);
  writeU32(bytes, 28, 0);
  writeU32(bytes, 32, packetLength);
  writeU32(bytes, 36, packetLength);

  const packet = 40;
  bytes.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], packet);
  writeU16(bytes, packet + 12, 0x0800);
  bytes[packet + 14] = 0x45;
  bytes[packet + 23] = 17;
  bytes.set([192, 0, 2, 1], packet + 26);
  bytes.set([198, 51, 100, 1], packet + 30);
  writeU16(bytes, packet + 34, 500);
  writeU16(bytes, packet + 36, 500);
  writeU16(bytes, packet + 38, 36);

  const ike = packet + 42;
  for (let index = 0; index < 8; index++) bytes[ike + index] = index + 1;
  bytes[ike + 16] = 0;
  bytes[ike + 17] = 0x20;
  bytes[ike + 18] = 34;
  writeU32(bytes, ike + 24, 28);

  return new File([bytes], 'ike-init.pcap', { type: 'application/vnd.tcpdump.pcap' });
}

function makeNatTEspPcap(): File {
  const payloadLength = 8 + 4;
  const packetLength = 14 + 20 + 8 + payloadLength;
  const bytes = new Uint8Array(24 + 16 + packetLength);
  writeU32(bytes, 0, 0xa1b2c3d4);
  writeU16(bytes, 4, 2);
  writeU16(bytes, 6, 4);
  writeU32(bytes, 16, 65535);
  writeU32(bytes, 20, 1);
  writeU32(bytes, 24, 1);
  writeU32(bytes, 32, packetLength);
  writeU32(bytes, 36, packetLength);
  const packet = 40;
  bytes.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], packet);
  writeU16(bytes, packet + 12, 0x0800);
  bytes[packet + 14] = 0x45;
  bytes[packet + 23] = 17;
  bytes.set([192, 0, 2, 1], packet + 26);
  bytes.set([198, 51, 100, 1], packet + 30);
  writeU16(bytes, packet + 34, 4500);
  writeU16(bytes, packet + 36, 4500);
  writeU16(bytes, packet + 38, payloadLength);
  writeU32(bytes, packet + 42, 0x12345678);
  writeU32(bytes, packet + 46, 7);
  bytes.set([1, 2, 3, 4], packet + 50);
  return new File([bytes], 'nat-t-esp.pcap', { type: 'application/vnd.tcpdump.pcap' });
}

function makeAhPcap(): File {
  const packetLength = 14 + 20 + 12;
  const bytes = new Uint8Array(24 + 16 + packetLength);
  writeU32(bytes, 0, 0xa1b2c3d4);
  writeU16(bytes, 4, 2);
  writeU16(bytes, 6, 4);
  writeU32(bytes, 16, 65535);
  writeU32(bytes, 20, 1);
  writeU32(bytes, 24, 1);
  writeU32(bytes, 32, packetLength);
  writeU32(bytes, 36, packetLength);
  const packet = 40;
  bytes.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], packet);
  writeU16(bytes, packet + 12, 0x0800);
  bytes[packet + 14] = 0x45;
  bytes[packet + 23] = 51;
  bytes.set([192, 0, 2, 1], packet + 26);
  bytes.set([198, 51, 100, 1], packet + 30);
  bytes[packet + 34] = 0;
  bytes[packet + 35] = 1;
  writeU32(bytes, packet + 38, 0x87654321);
  writeU32(bytes, packet + 42, 9);
  return new File([bytes], 'ah.pcap', { type: 'application/vnd.tcpdump.pcap' });
}

function makePcapNg(): File {
  const bytes = new Uint8Array(84);
  writeU32(bytes, 0, 0x0a0d0d0a);
  writeU32(bytes, 4, 28);
  writeU32(bytes, 8, 0x1a2b3c4d);
  writeU16(bytes, 12, 1);
  writeU16(bytes, 14, 0);
  writeU32(bytes, 16, 0xffffffff);
  writeU32(bytes, 20, 0xffffffff);
  writeU32(bytes, 24, 28);

  writeU32(bytes, 28, 1);
  writeU32(bytes, 32, 20);
  writeU16(bytes, 36, 1);
  writeU16(bytes, 38, 0);
  writeU32(bytes, 40, 65535);
  writeU32(bytes, 44, 20);

  writeU32(bytes, 48, 6);
  writeU32(bytes, 52, 36);
  writeU32(bytes, 56, 0);
  writeU32(bytes, 60, 0);
  writeU32(bytes, 64, 1000);
  writeU32(bytes, 68, 4);
  writeU32(bytes, 72, 4);
  bytes.set([0xde, 0xad, 0xbe, 0xef], 76);
  writeU32(bytes, 80, 36);
  return new File([bytes], 'capture.pcapng', { type: 'application/pcapng' });
}

function makeEncryptedIkePcap(): File {
  const packetLength = 14 + 20 + 8 + 36;
  const bytes = new Uint8Array(24 + 16 + packetLength);
  writeU32(bytes, 0, 0xa1b2c3d4);
  writeU16(bytes, 4, 2);
  writeU16(bytes, 6, 4);
  writeU32(bytes, 16, 65535);
  writeU32(bytes, 20, 1);
  writeU32(bytes, 24, 1);
  writeU32(bytes, 32, packetLength);
  writeU32(bytes, 36, packetLength);
  const packet = 40;
  bytes.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], packet);
  writeU16(bytes, packet + 12, 0x0800);
  bytes[packet + 14] = 0x45;
  bytes[packet + 23] = 17;
  bytes.set([192, 0, 2, 1], packet + 26);
  bytes.set([198, 51, 100, 1], packet + 30);
  writeU16(bytes, packet + 34, 500);
  writeU16(bytes, packet + 36, 500);
  writeU16(bytes, packet + 38, 36);
  const ike = packet + 42;
  bytes[ike + 16] = 46;
  bytes[ike + 17] = 0x20;
  bytes[ike + 18] = 35;
  writeU32(bytes, ike + 24, 36);
  bytes[ike + 28] = 0;
  bytes[ike + 29] = 0;
  writeU16(bytes, ike + 30, 8);
  bytes.set([0xaa, 0xbb, 0xcc, 0xdd], ike + 32);
  return new File([bytes], 'encrypted-ike-auth.pcap', { type: 'application/vnd.tcpdump.pcap' });
}

test('parses an observed IKEv2 header from packet bytes', async () => {
  const result = await parseUploadedFile(makeIkeV2Pcap());
  assert.equal(result.packets.length, 1);
  assert.equal(result.packets[0].protocol, 'IKE');
  assert.equal(result.sa.ikeVersion, 'IKEv2');
  assert.equal(result.sa.initiatorSpi, '0x0102030405060708');
  assert.equal(result.sa.encryptionAlgorithm, 'Not observed in capture');

  const evidence = addSecurityAssociationEvidence(result.sa).fieldEvidence;
  assert.equal(evidence?.ike_version.status, 'OBSERVED');
  assert.equal(evidence?.ike_version.source, 'PCAP_OBSERVED');
  assert.equal(evidence?.ike_encryption.status, 'NOT_DETERMINABLE');
  assert.equal(evidence?.pfs.status, 'NOT_DETERMINABLE');
});

test('does not classify an insufficient ESP sample', () => {
  const prediction = classifyEspTraffic({
    packetCount: 2,
    totalBytes: 2000,
    meanPacketLength: 1000,
    stdPacketLength: 0,
    minPacketLength: 1000,
    maxPacketLength: 1000,
    meanInterArrivalTimeMs: 10,
    burstRatio: 0.5,
    flowSymmetry: 1,
    calculatedEntropy: 7.5,
  });
  assert.equal(prediction.predictedClass, 'INSUFFICIENT_DATA');
  assert.equal(prediction.confidenceScore, 0);
  assert.equal(prediction.status, 'NOT_DETERMINABLE');
});

test('classifies UDP 4500 ESP without a non-ESP marker as ESP', async () => {
  const result = await parseUploadedFile(makeNatTEspPcap());
  assert.equal(result.packets[0].protocol, 'ESP');
  assert.equal(result.packets[0].spi, '0x12345678');
  assert.equal(result.packets[0].seq, 7);
  assert.equal(result.sa.observations?.natTraversal, 'Detected');
  assert.equal(result.features.packetCount, 1);
});

test('extracts AH SPI and sequence evidence', async () => {
  const result = await parseUploadedFile(makeAhPcap());
  assert.equal(result.packets[0].protocol, 'AH');
  assert.equal(result.packets[0].spi, '0x87654321');
  assert.equal(result.packets[0].seq, 9);
  assert.deepEqual(result.sa.observations?.ahSpis, ['0x87654321']);
  assert.equal(result.sa.observations?.ahSequenceRange, '9 - 9');
});

test('parses a valid PCAPNG enhanced packet block', async () => {
  const result = await parseUploadedFile(makePcapNg());
  assert.equal(result.packets.length, 1);
  assert.equal(result.fileSizeBytes, 84);
  assert.equal(result.packets[0].protocol, 'OTHER');
});

test('rejects truncated capture input safely', async () => {
  await assert.rejects(
    parseUploadedFile(new File([new Uint8Array([0x0a, 0x0d, 0x0d])], 'truncated.pcapng')),
    /too small/i
  );
});

test('does not infer Child-SA crypto from encrypted IKE_AUTH', async () => {
  const result = await parseUploadedFile(makeEncryptedIkePcap());
  assert.equal(result.sa.ikeVersion, 'IKEv2');
  assert.equal(result.sa.encryptionAlgorithm, 'Not observed in capture');
  assert.equal(result.sa.dhGroup, 'Not observed in capture');
  assert.equal(result.sa.pfsEnabled, null);
  assert.equal(result.sa.observations?.captureNotes.length, 1);
});
