/**
 * AFIA — Aircraft Fault Interpreter & Assistant
 * Full-Stack Backend (single-file build)
 *
 * Stack: Node.js + Express + PostgreSQL (Neon) + JWT
 * Deploy target: Render (Web Service)
 *
 * ---------------------------------------------------------------------------
 * ENVIRONMENT VARIABLES (set these in Render → Environment)
 * ---------------------------------------------------------------------------
 *   DATABASE_URL     Neon connection string, e.g.
 *                     postgresql://user:pass@ep-xxxx.neon.tech/afia?sslmode=require
 *   JWT_SECRET        Long random string used to sign auth tokens
 *   CORS_ORIGIN       Comma-separated list of allowed origins, e.g.
 *                      https://afia.vercel.app,http://localhost:5500
 *                      (use "*" during development to allow any origin)
 *   PORT              Provided automatically by Render — do not hardcode
 *
 * On boot this file automatically:
 *   1. Connects to Neon PostgreSQL
 *   2. Creates every table from PRD §9 if it doesn't already exist
 *   3. Seeds reference data (manufacturers, families, models, ATA chapters)
 *      and a starter set of educational/reference fault records so the
 *      Search screen returns real results immediately after deploy.
 *
 * All routes are namespaced under /api/v1 to match the PRD (§10) and the
 * endpoints already referenced in the frontend build (AFIA_Frontend.html).
 * ---------------------------------------------------------------------------
 */

'use strict';

require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const PDFDocument = require('pdfkit');
const crypto = require('crypto');

// -----------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not set. Add your Neon connection string to the environment.');
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Add a long random secret to the environment.');
  process.exit(1);
}

const ALLOWED_ORIGINS = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

// -----------------------------------------------------------------------
// Database
// -----------------------------------------------------------------------
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Neon
});

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool error:', err);
});

// -----------------------------------------------------------------------
// Schema + seed data
// -----------------------------------------------------------------------
const SCHEMA_SQL = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS manufacturers (
  id            SERIAL PRIMARY KEY,
  name          TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS aircraft_families (
  id              SERIAL PRIMARY KEY,
  manufacturer_id INTEGER NOT NULL REFERENCES manufacturers(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  code            TEXT,
  UNIQUE(manufacturer_id, name)
);

CREATE TABLE IF NOT EXISTS aircraft_models (
  id         SERIAL PRIMARY KEY,
  family_id  INTEGER NOT NULL REFERENCES aircraft_families(id) ON DELETE CASCADE,
  name       TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS ata_chapters (
  id         SERIAL PRIMARY KEY,
  code       TEXT UNIQUE NOT NULL,
  name       TEXT NOT NULL,
  subsystem  TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_type        TEXT NOT NULL DEFAULT 'Individual' CHECK (account_type IN ('Individual','Company')),
  full_name           TEXT NOT NULL,
  company_name        TEXT,
  country             TEXT,
  phone               TEXT,
  email               TEXT UNIQUE NOT NULL,
  role                TEXT,
  password_hash       TEXT NOT NULL,
  offline_cache       BOOLEAN NOT NULL DEFAULT true,
  email_notifications BOOLEAN NOT NULL DEFAULT false,
  dark_sidebar        BOOLEAN NOT NULL DEFAULT true,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS aircraft_faults (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_code         TEXT NOT NULL,
  message_system       TEXT NOT NULL,           -- ECAM / EICAS / CMC / BITE
  aircraft_model       TEXT NOT NULL,            -- e.g. A320, 737 MAX
  ata_chapter_code     TEXT REFERENCES ata_chapters(code),
  severity             TEXT NOT NULL CHECK (severity IN ('Critical','High','Medium','Low')),
  explanation          TEXT NOT NULL,
  probable_causes      TEXT[] NOT NULL DEFAULT '{}',
  maintenance_actions  TEXT[] NOT NULL DEFAULT '{}',
  reference_notes      TEXT[] NOT NULL DEFAULT '{}',
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_faults_model    ON aircraft_faults (aircraft_model);
CREATE INDEX IF NOT EXISTS idx_faults_ata       ON aircraft_faults (ata_chapter_code);
CREATE INDEX IF NOT EXISTS idx_faults_severity  ON aircraft_faults (severity);
CREATE INDEX IF NOT EXISTS idx_faults_message   ON aircraft_faults USING GIN (to_tsvector('english', message_code || ' ' || explanation));

CREATE TABLE IF NOT EXISTS fault_history (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  fault_id       UUID REFERENCES aircraft_faults(id) ON DELETE SET NULL,
  query_message  TEXT,
  query_model    TEXT,
  query_ata      TEXT,
  query_severity TEXT,
  note           TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_history_user ON fault_history (user_id, created_at DESC);
`;

const ATA_CHAPTERS = [
  { code: '21', name: 'Air Conditioning', subsystem: 'Pressurization & environmental' },
  { code: '22', name: 'Auto Flight', subsystem: 'Autopilot & flight guidance' },
  { code: '23', name: 'Communications', subsystem: 'Radios & data links' },
  { code: '24', name: 'Electrical Power', subsystem: 'Generation & distribution' },
  { code: '27', name: 'Flight Controls', subsystem: 'Primary & secondary controls' },
  { code: '28', name: 'Fuel', subsystem: 'Storage, feed & indication' },
  { code: '29', name: 'Hydraulic Power', subsystem: 'Generation & distribution' },
  { code: '31', name: 'Indicating / Recording', subsystem: 'Instruments & data recorders' },
  { code: '32', name: 'Landing Gear', subsystem: 'Extension, retraction & brakes' },
  { code: '34', name: 'Navigation', subsystem: 'Air data, radio nav & displays' },
  { code: '71', name: 'Powerplant', subsystem: 'Engine installation' },
];

const MANUFACTURERS = ['Airbus', 'Boeing'];

const FAMILIES = [
  { manufacturer: 'Airbus', name: 'A320 Family', code: 'A320' },
  { manufacturer: 'Boeing', name: '737 NG/MAX', code: '737' },
];

const MODELS = [
  { family: 'A320 Family', name: 'A319' },
  { family: 'A320 Family', name: 'A320' },
  { family: 'A320 Family', name: 'A321' },
  { family: '737 NG/MAX', name: '737 NG' },
  { family: '737 NG/MAX', name: '737 MAX' },
];

// Educational / reference-style fault records only — general knowledge write-ups,
// not verbatim excerpts from any proprietary AMM/FIM/TSM (per PRD §17).
const FAULTS = [
  {
    message_code: 'ELEC GEN 1 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '24', severity: 'High',
    explanation: 'Generator 1 has been automatically disconnected from the electrical network because a protection function detected an abnormal condition (e.g. over/under voltage, over/under frequency, or a differential fault).',
    causes: ['Generator control unit (GCU) fault', 'Internal generator winding fault', 'Wiring or connector fault between the generator and GCU', 'Drive (IDG/CSD) related fault'],
    actions: ['Confirm GEN 1 fault indication and check associated ECAM procedure', 'Attempt reset per applicable procedure if authorized', 'Monitor remaining electrical power sources', 'Inspect generator and wiring at next maintenance opportunity', 'Report to maintenance control if fault persists after reset'],
    refs: ['Refer to operator AMM/TSM 24-XX for certified troubleshooting', 'Cross-check applicable MEL item for dispatch'],
  },
  {
    message_code: 'ELEC GEN 2 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '24', severity: 'High',
    explanation: 'Generator 2 has been disconnected by protection logic following detection of an abnormal electrical parameter on that channel.',
    causes: ['GCU fault on channel 2', 'Generator internal fault', 'Feeder or contactor fault'],
    actions: ['Check ECAM status page for associated system impact', 'Verify bus tie and electrical configuration', 'Attempt reset if procedure allows', 'Schedule generator/GCU inspection'],
    refs: ['Refer to operator AMM/TSM 24-XX for certified troubleshooting'],
  },
  {
    message_code: 'ELEC BAT 1 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '24', severity: 'Medium',
    explanation: 'Battery 1 charging or monitoring circuit has detected a fault condition, such as abnormal charge current, low capacity, or a sensor discrepancy.',
    causes: ['Degraded battery cells', 'Battery charge limiter fault', 'Wiring/connector corrosion'],
    actions: ['Check battery voltage and temperature indications', 'Inspect battery per scheduled maintenance if due', 'Replace battery if capacity test fails'],
    refs: ['Refer to operator AMM 24-XX battery maintenance practices'],
  },
  {
    message_code: 'HYD G SYS LO PR', message_system: 'ECAM', aircraft_model: 'A320', ata: '29', severity: 'Critical',
    explanation: 'Green hydraulic system pressure has dropped below the normal operating range, indicating a possible leak, pump fault, or reservoir depletion.',
    causes: ['External or internal hydraulic leak', 'Engine-driven pump (EDP) failure', 'Reservoir low quantity', 'Pressure transducer fault'],
    actions: ['Cross-check hydraulic quantity and pressure indications', 'Visually inspect for external leaks at next opportunity', 'Isolate affected system per ECAM guidance', 'Do not dispatch with confirmed leak until rectified'],
    refs: ['Refer to operator AMM/TSM 29-XX for certified troubleshooting', 'Cross-check applicable MEL item'],
  },
  {
    message_code: 'HYD Y SYS LO PR', message_system: 'ECAM', aircraft_model: 'A320', ata: '29', severity: 'Critical',
    explanation: 'Yellow hydraulic system pressure is below normal range; may affect systems powered exclusively by this circuit.',
    causes: ['Hydraulic leak in yellow system lines', 'Electric pump fault', 'Reservoir air/quantity issue'],
    actions: ['Verify quantity and pressure trend on ECAM', 'Inspect for leaks on ground', 'Check pump circuit breakers and electrical supply'],
    refs: ['Refer to operator AMM/TSM 29-XX for certified troubleshooting'],
  },
  {
    message_code: 'F/CTL SEC 1 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '27', severity: 'High',
    explanation: 'Spoiler Elevator Computer 1 has detected an internal fault or lost required data, degrading redundancy in the flight control system.',
    causes: ['SEC internal hardware fault', 'Loss of input data from associated sensors', 'Power supply interruption to the computer'],
    actions: ['Note ECAM status page for affected control surfaces', 'Perform SEC reset only if procedure authorizes', 'Have computer tested/replaced if fault repeats'],
    refs: ['Refer to operator AMM/TSM 27-XX for certified troubleshooting'],
  },
  {
    message_code: 'F/CTL ELAC 1 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '27', severity: 'High',
    explanation: 'Elevator Aileron Computer 1 fault detected; flight control law may revert to an alternate or degraded mode.',
    causes: ['ELAC internal fault', 'Sensor/input signal fault', 'Electrical power interruption'],
    actions: ['Confirm flight control law annunciation', 'Follow ECAM abnormal procedure', 'Inspect/replace ELAC if fault is repetitive'],
    refs: ['Refer to operator AMM/TSM 27-XX for certified troubleshooting'],
  },
  {
    message_code: 'FUEL L(R) TK PUMP LO PR', message_system: 'ECAM', aircraft_model: 'A320', ata: '28', severity: 'Medium',
    explanation: 'Low pressure has been detected at the output of a fuel tank pump, which can reduce feed redundancy to the associated engine.',
    causes: ['Fuel pump wear or failure', 'Low fuel quantity in tank', 'Fuel pump electrical supply fault'],
    actions: ['Check fuel quantity and balance', 'Monitor for repeat occurrence', 'Have pump tested/replaced if fault is confirmed on ground'],
    refs: ['Refer to operator AMM/TSM 28-XX for certified troubleshooting'],
  },
  {
    message_code: 'L(R) GEAR NOT DOWNLOCKED', message_system: 'ECAM', aircraft_model: 'A320', ata: '32', severity: 'Critical',
    explanation: 'A landing gear downlock indication has not been confirmed, which may indicate a mechanical, sensor, or hydraulic issue in the extension system.',
    causes: ['Downlock proximity sensor fault', 'Mechanical linkage misadjustment', 'Hydraulic actuation issue'],
    actions: ['Attempt alternate/emergency extension per ECAM procedure', 'Perform visual gear position check if possible', 'Ground inspection of downlock sensors and mechanism required before further flight'],
    refs: ['Refer to operator AMM/TSM 32-XX for certified troubleshooting'],
  },
  {
    message_code: 'NAV ADR 1 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '34', severity: 'Medium',
    explanation: 'Air Data Reference 1 has flagged invalid or inconsistent air data parameters (altitude, airspeed, or angle of attack related data).',
    causes: ['Pitot/static probe blockage or fault', 'ADR internal computation fault', 'Wiring fault to associated sensors'],
    actions: ['Cross-check ADR data against other sources', 'Inspect pitot/static probes for obstruction or damage', 'Have ADIRU tested if fault persists'],
    refs: ['Refer to operator AMM/TSM 34-XX for certified troubleshooting'],
  },
  {
    message_code: 'AUTO FLT AP OFF', message_system: 'ECAM', aircraft_model: 'A320', ata: '22', severity: 'Low',
    explanation: 'The autopilot has disconnected, which can occur due to a pilot command, a system fault, or a monitored parameter exceeding a limit.',
    causes: ['Manual disconnect', 'Flight control computer fault', 'Invalid input data to the autopilot'],
    actions: ['Confirm disconnect was intentional', 'Review associated fault messages if unintentional', 'Have flight control/autoflight computers checked if unexplained'],
    refs: ['Refer to operator AMM/TSM 22-XX for certified troubleshooting'],
  },
  {
    message_code: 'AIR COND PACK 1 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '21', severity: 'Medium',
    explanation: 'Pack 1 has been automatically shut down or degraded due to an abnormal temperature, valve position, or overheat condition.',
    causes: ['Pack valve fault', 'Overheat/temperature sensor fault', 'Pack controller fault'],
    actions: ['Monitor cabin temperature and pressurization', 'Reset pack per procedure if authorized', 'Inspect pack valves and sensors on ground'],
    refs: ['Refer to operator AMM/TSM 21-XX for certified troubleshooting'],
  },
  {
    message_code: 'COMM VHF 1 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '23', severity: 'Low',
    explanation: 'VHF radio 1 has reported an internal fault, reducing communication redundancy.',
    causes: ['Radio internal hardware fault', 'Antenna or coax cable fault', 'Power supply interruption'],
    actions: ['Verify communications on remaining VHF sets', 'Cycle radio per procedure if authorized', 'Have radio bench-tested if fault repeats'],
    refs: ['Refer to operator AMM/TSM 23-XX for certified troubleshooting'],
  },
  {
    message_code: 'IRS 1 FAULT', message_system: 'ECAM', aircraft_model: 'A320', ata: '34', severity: 'High',
    explanation: 'Inertial Reference System 1 has detected an internal fault affecting attitude, heading, or navigation data output.',
    causes: ['IRS internal hardware fault', 'Alignment failure', 'Power interruption during alignment'],
    actions: ['Cross-check attitude/heading with remaining IRS units', 'Attempt realignment on ground per procedure', 'Have unit replaced if fault is repetitive'],
    refs: ['Refer to operator AMM/TSM 34-XX for certified troubleshooting'],
  },
  {
    message_code: 'ENG 1 EGT OVER LIMIT', message_system: 'EICAS', aircraft_model: '737 NG', ata: '71', severity: 'Critical',
    explanation: 'Engine 1 exhaust gas temperature has exceeded the normal operating limit, indicating a possible internal engine distress condition.',
    causes: ['Internal engine mechanical distress', 'EGT sensor/harness fault', 'Fuel control unit malfunction'],
    actions: ['Follow QRH engine limit exceedance procedure', 'Do not dispatch until engine is inspected', 'Borescope inspection recommended before further flight'],
    refs: ['Refer to operator AMM/FIM 71-XX for certified troubleshooting'],
  },
  {
    message_code: 'ELEC BUS OFF', message_system: 'EICAS', aircraft_model: '737 NG', ata: '24', severity: 'High',
    explanation: 'An electrical bus has been de-energized, either automatically by protection logic or due to a source fault.',
    causes: ['Generator/transformer-rectifier fault', 'Bus protection trip', 'Wiring fault on the affected bus'],
    actions: ['Check associated system losses on EICAS', 'Attempt bus reset only per authorized procedure', 'Inspect source and bus tie components on ground'],
    refs: ['Refer to operator AMM/FIM 24-XX for certified troubleshooting'],
  },
  {
    message_code: 'HYD SYS A PRESS LOW', message_system: 'EICAS', aircraft_model: '737 NG', ata: '29', severity: 'Critical',
    explanation: 'System A hydraulic pressure is below normal range, which may be caused by a leak, pump failure, or reservoir depletion.',
    causes: ['Hydraulic leak', 'Engine-driven pump fault', 'Electric pump fault or low reservoir quantity'],
    actions: ['Cross-check quantity and pressure trend', 'Inspect for leaks on ground before further dispatch', 'Verify pump circuit breaker status'],
    refs: ['Refer to operator AMM/FIM 29-XX for certified troubleshooting'],
  },
  {
    message_code: 'FLT CONTROL FAULT', message_system: 'EICAS', aircraft_model: '737 MAX', ata: '27', severity: 'High',
    explanation: 'A flight control system fault has been detected, which may affect control surface authority or feel/feedback systems.',
    causes: ['Flight control computer internal fault', 'Sensor or actuator discrepancy', 'Wiring/power interruption'],
    actions: ['Follow QRH non-normal checklist for the specific annunciation', 'Do not dispatch with unresolved flight control faults', 'Have affected LRU tested/replaced on ground'],
    refs: ['Refer to operator AMM/FIM 27-XX for certified troubleshooting'],
  },
  {
    message_code: 'FUEL PRESS LOW', message_system: 'EICAS', aircraft_model: '737 MAX', ata: '28', severity: 'Medium',
    explanation: 'Fuel pressure at the engine feed has dropped below the normal range, which can reduce feed redundancy.',
    causes: ['Fuel pump degradation', 'Low fuel quantity', 'Fuel filter contamination'],
    actions: ['Check fuel quantity/balance', 'Monitor engine parameters for related trends', 'Inspect fuel pump and filter on ground if repeated'],
    refs: ['Refer to operator AMM/FIM 28-XX for certified troubleshooting'],
  },
  {
    message_code: 'GEAR DISAGREE', message_system: 'EICAS', aircraft_model: '737 MAX', ata: '32', severity: 'Critical',
    explanation: 'A landing gear position indication disagrees with the commanded position, which may reflect a sensor, mechanical, or hydraulic issue.',
    causes: ['Proximity sensor fault', 'Mechanical rigging issue', 'Hydraulic actuation fault'],
    actions: ['Follow QRH gear disagree non-normal procedure', 'Perform visual/alternate gear indication check if available', 'Ground inspection required before further flight if unresolved'],
    refs: ['Refer to operator AMM/FIM 32-XX for certified troubleshooting'],
  },
  {
    message_code: 'AUTOPILOT DISCONNECT', message_system: 'EICAS', aircraft_model: '737 NG', ata: '22', severity: 'Low',
    explanation: 'The autopilot has disconnected either through manual pilot action or an internal monitor detecting an abnormal condition.',
    causes: ['Manual disconnect', 'Autoflight computer internal fault', 'Invalid sensor input to the autoflight system'],
    actions: ['Confirm whether disconnect was commanded', 'Review associated EICAS messages if unexpected', 'Have autoflight computer checked if fault is repetitive'],
    refs: ['Refer to operator AMM/FIM 22-XX for certified troubleshooting'],
  },
  {
    message_code: 'PACK 1 OVERHEAT', message_system: 'EICAS', aircraft_model: '737 NG', ata: '21', severity: 'Medium',
    explanation: 'Pack 1 has reported an overheat condition, typically resulting in automatic shutdown of that pack to protect downstream ducting.',
    causes: ['Pack valve stuck or fault', 'Overheat sensor fault', 'Restricted duct airflow'],
    actions: ['Monitor cabin temperature and remaining pack operation', 'Reset pack per procedure if authorized', 'Inspect valves/ducting on ground'],
    refs: ['Refer to operator AMM/FIM 21-XX for certified troubleshooting'],
  },
  {
    message_code: 'VHF COMM 1 FAIL', message_system: 'EICAS', aircraft_model: '737 MAX', ata: '23', severity: 'Low',
    explanation: 'VHF communication radio 1 has failed a self-test or reported an internal fault.',
    causes: ['Radio internal fault', 'Antenna/coax fault', 'Power supply interruption'],
    actions: ['Verify communications on remaining radios', 'Cycle radio per procedure if authorized', 'Bench-test/replace radio if fault repeats'],
    refs: ['Refer to operator AMM/FIM 23-XX for certified troubleshooting'],
  },
  {
    message_code: 'IRS 2 FAULT', message_system: 'EICAS', aircraft_model: '737 NG', ata: '34', severity: 'High',
    explanation: 'Inertial Reference System 2 has an internal fault affecting attitude, heading, or navigation output.',
    causes: ['IRS internal hardware fault', 'Alignment error', 'Power interruption'],
    actions: ['Cross-check attitude/heading against remaining IRS', 'Attempt realignment on ground', 'Replace unit if fault is repetitive'],
    refs: ['Refer to operator AMM/FIM 34-XX for certified troubleshooting'],
  },
  {
    message_code: 'ELEC GEN 1 FAULT', message_system: 'EICAS', aircraft_model: '737 MAX', ata: '24', severity: 'High',
    explanation: 'Generator 1 has been disconnected from the electrical network by protection logic following an abnormal parameter detection.',
    causes: ['Generator control unit fault', 'Internal generator fault', 'Wiring/connector fault'],
    actions: ['Check EICAS for associated system impact', 'Attempt reset only if procedure authorizes', 'Inspect generator/GCU on ground'],
    refs: ['Refer to operator AMM/FIM 24-XX for certified troubleshooting'],
  },
  {
    message_code: 'CAB PRESS AUTO FAULT', message_system: 'ECAM', aircraft_model: 'A321', ata: '21', severity: 'High',
    explanation: 'The automatic cabin pressure controller has faulted, typically requiring the crew to revert to a backup/manual pressurization mode.',
    causes: ['Pressurization controller internal fault', 'Outflow valve position sensor fault', 'Wiring fault to the controller'],
    actions: ['Select alternate/manual pressurization mode per ECAM procedure', 'Monitor cabin altitude and rate closely', 'Inspect controller and outflow valve system on ground'],
    refs: ['Refer to operator AMM/TSM 21-XX for certified troubleshooting'],
  },
  {
    message_code: 'BRAKES ANTI SKID FAULT', message_system: 'ECAM', aircraft_model: 'A319', ata: '32', severity: 'Medium',
    explanation: 'The anti-skid braking system has detected a fault, reducing or disabling automatic skid protection on landing/rejected takeoff.',
    causes: ['Wheel speed sensor fault', 'Anti-skid control unit fault', 'Wiring fault to a sensor or valve'],
    actions: ['Note performance impact for landing distance calculations', 'Inspect wheel speed sensors and wiring on ground', 'Have anti-skid control unit tested if fault repeats'],
    refs: ['Refer to operator AMM/TSM 32-XX for certified troubleshooting'],
  },
];

async function ensureSchema() {
  const client = await pool.connect();
  try {
    await client.query(SCHEMA_SQL);
    console.log('Schema verified/created.');
  } finally {
    client.release();
  }
}

async function seedIfEmpty() {
  const client = await pool.connect();
  try {
    // ATA chapters
    for (const c of ATA_CHAPTERS) {
      await client.query(
        `INSERT INTO ata_chapters (code, name, subsystem) VALUES ($1,$2,$3)
         ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name, subsystem = EXCLUDED.subsystem`,
        [c.code, c.name, c.subsystem]
      );
    }

    // Manufacturers
    const mfrIds = {};
    for (const name of MANUFACTURERS) {
      const res = await client.query(
        `INSERT INTO manufacturers (name) VALUES ($1)
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`,
        [name]
      );
      mfrIds[name] = res.rows[0].id;
    }

    // Families
    const famIds = {};
    for (const f of FAMILIES) {
      const res = await client.query(
        `INSERT INTO aircraft_families (manufacturer_id, name, code) VALUES ($1,$2,$3)
         ON CONFLICT (manufacturer_id, name) DO UPDATE SET code = EXCLUDED.code RETURNING id`,
        [mfrIds[f.manufacturer], f.name, f.code]
      );
      famIds[f.name] = res.rows[0].id;
    }

    // Models
    for (const m of MODELS) {
      await client.query(
        `INSERT INTO aircraft_models (family_id, name) VALUES ($1,$2)
         ON CONFLICT (name) DO NOTHING`,
        [famIds[m.family], m.name]
      );
    }

    // Faults — only seed if table is empty, to avoid duplicating on every boot
    const { rows } = await client.query('SELECT COUNT(*)::int AS n FROM aircraft_faults');
    if (rows[0].n === 0) {
      for (const f of FAULTS) {
        await client.query(
          `INSERT INTO aircraft_faults
            (message_code, message_system, aircraft_model, ata_chapter_code, severity, explanation, probable_causes, maintenance_actions, reference_notes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [f.message_code, f.message_system, f.aircraft_model, f.ata, f.severity, f.explanation, f.causes, f.actions, f.refs]
        );
      }
      console.log(`Seeded ${FAULTS.length} reference fault records.`);
    }
  } finally {
    client.release();
  }
}

// -----------------------------------------------------------------------
// App setup
// -----------------------------------------------------------------------
const app = express();

app.set('trust proxy', 1); // Render sits behind a proxy — needed for correct rate-limit IPs

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true); // curl / server-to-server / mobile apps
      if (ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
  })
);

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many auth attempts. Please try again later.' },
});

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function publicUser(u) {
  return {
    id: u.id,
    accountType: u.account_type,
    name: u.full_name,
    company: u.company_name,
    country: u.country,
    phone: u.phone,
    email: u.email,
    role: u.role,
    preferences: {
      offlineCache: u.offline_cache,
      emailNotifications: u.email_notifications,
      darkSidebar: u.dark_sidebar,
    },
    createdAt: u.created_at,
  };
}

function isEmail(v) {
  return typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

async function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing or invalid Authorization header.' });

    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [payload.sub]);
    if (!rows[0]) return res.status(401).json({ error: 'User no longer exists.' });

    req.user = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// -----------------------------------------------------------------------
// Health check (Render)
// -----------------------------------------------------------------------
app.get('/', (req, res) => {
  res.json({ service: 'AFIA API', status: 'ok', version: '1.0.0' });
});

app.get('/healthz', asyncHandler(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ status: 'ok', db: 'connected', time: new Date().toISOString() });
}));

// -----------------------------------------------------------------------
// AUTH ROUTES  — /api/v1/auth/*
// -----------------------------------------------------------------------
const authRouter = express.Router();

authRouter.post(
  '/signup',
  authLimiter,
  asyncHandler(async (req, res) => {
    const {
      accountType = 'Individual',
      name,
      company,
      country,
      phone,
      email,
      role,
      password,
    } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email and password are required.' });
    }
    if (!isEmail(email)) {
      return res.status(400).json({ error: 'A valid email address is required.' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (!['Individual', 'Company'].includes(accountType)) {
      return res.status(400).json({ error: 'accountType must be Individual or Company.' });
    }
    if (accountType === 'Company' && !company) {
      return res.status(400).json({ error: 'company is required for Company accounts.' });
    }

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows[0]) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { rows } = await pool.query(
      `INSERT INTO users (account_type, full_name, company_name, country, phone, email, role, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [accountType, name, company || null, country || null, phone || null, email.toLowerCase(), role || null, passwordHash]
    );

    const user = rows[0];
    const token = signToken(user);
    res.status(201).json({ token, user: publicUser(user) });
  })
);

authRouter.post(
  '/login',
  authLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required.' });
    }

    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [String(email).toLowerCase()]);
    const user = rows[0];
    if (!user) {
      return res.status(401).json({ error: "We couldn't find an account with those details." });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "We couldn't find an account with those details." });
    }

    const token = signToken(user);
    res.json({ token, user: publicUser(user) });
  })
);

authRouter.get(
  '/me',
  authRequired,
  asyncHandler(async (req, res) => {
    res.json({ user: publicUser(req.user) });
  })
);

authRouter.put(
  '/me',
  authRequired,
  asyncHandler(async (req, res) => {
    const { name, role, offlineCache, emailNotifications, darkSidebar } = req.body || {};

    const { rows } = await pool.query(
      `UPDATE users SET
         full_name           = COALESCE($1, full_name),
         role                = COALESCE($2, role),
         offline_cache       = COALESCE($3, offline_cache),
         email_notifications = COALESCE($4, email_notifications),
         dark_sidebar        = COALESCE($5, dark_sidebar),
         updated_at          = now()
       WHERE id = $6
       RETURNING *`,
      [
        name ?? null,
        role ?? null,
        typeof offlineCache === 'boolean' ? offlineCache : null,
        typeof emailNotifications === 'boolean' ? emailNotifications : null,
        typeof darkSidebar === 'boolean' ? darkSidebar : null,
        req.user.id,
      ]
    );

    res.json({ user: publicUser(rows[0]) });
  })
);

authRouter.put(
  '/password',
  authRequired,
  asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'currentPassword and newPassword are required.' });
    }
    if (String(newPassword).length < 8) {
      return res.status(400).json({ error: 'newPassword must be at least 8 characters.' });
    }

    const ok = await bcrypt.compare(currentPassword, req.user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Current password is incorrect.' });

    const newHash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2', [newHash, req.user.id]);
    res.json({ message: 'Password updated successfully.' });
  })
);

app.use('/api/v1/auth', authRouter);

// -----------------------------------------------------------------------
// AIRCRAFT REFERENCE ROUTES — /api/v1/aircraft/*
// -----------------------------------------------------------------------
const aircraftRouter = express.Router();

aircraftRouter.get(
  '/models',
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT m.id, m.name, f.name AS family, mf.name AS manufacturer
       FROM aircraft_models m
       JOIN aircraft_families f ON f.id = m.family_id
       JOIN manufacturers mf ON mf.id = f.manufacturer_id
       ORDER BY mf.name, f.name, m.name`
    );
    res.json({ models: rows });
  })
);

aircraftRouter.get(
  '/ata-chapters',
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query('SELECT code, name, subsystem FROM ata_chapters ORDER BY code::int');
    res.json({ chapters: rows });
  })
);

// GET /api/v1/aircraft/faults/search?message=&model=&ata=&severity=&page=&limit=
aircraftRouter.get(
  '/faults/search',
  asyncHandler(async (req, res) => {
    const { message = '', model = '', severity = '' } = req.query;
    let { ata = '' } = req.query;

    // The frontend's ATA select can send either a bare code ("21") or the
    // display string ("ATA 21 — Air Conditioning"); normalize to the code.
    const ataMatch = String(ata).match(/(\d{2})/);
    ata = ataMatch ? ataMatch[1] : '';

    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
    const offset = (page - 1) * limit;

    const clauses = [];
    const params = [];

    if (message.trim()) {
      params.push(`%${message.trim()}%`);
      clauses.push(`(message_code ILIKE $${params.length} OR explanation ILIKE $${params.length})`);
    }
    if (model.trim()) {
      params.push(model.trim());
      clauses.push(`aircraft_model = $${params.length}`);
    }
    if (ata) {
      params.push(ata);
      clauses.push(`ata_chapter_code = $${params.length}`);
    }
    if (severity.trim()) {
      params.push(severity.trim());
      clauses.push(`severity = $${params.length}`);
    }

    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

    const countRes = await pool.query(`SELECT COUNT(*)::int AS n FROM aircraft_faults ${where}`, params);
    const total = countRes.rows[0].n;

    params.push(limit);
    params.push(offset);
    const dataRes = await pool.query(
      `SELECT af.*, ac.name AS ata_chapter_name
       FROM aircraft_faults af
       LEFT JOIN ata_chapters ac ON ac.code = af.ata_chapter_code
       ${where}
       ORDER BY af.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    res.json({
      results: dataRes.rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    });
  })
);

aircraftRouter.get(
  '/faults/:id',
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT af.*, ac.name AS ata_chapter_name
       FROM aircraft_faults af
       LEFT JOIN ata_chapters ac ON ac.code = af.ata_chapter_code
       WHERE af.id = $1`,
      [req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Fault record not found.' });
    res.json({ fault: rows[0] });
  })
);

app.use('/api/v1/aircraft', aircraftRouter);

// -----------------------------------------------------------------------
// HISTORY ROUTES — /api/v1/history  (all require auth)
// -----------------------------------------------------------------------
const historyRouter = express.Router();
historyRouter.use(authRequired);

historyRouter.post(
  '/',
  asyncHandler(async (req, res) => {
    const { faultId, queryMessage, queryModel, queryAta, querySeverity, note } = req.body || {};

    if (faultId) {
      const check = await pool.query('SELECT id FROM aircraft_faults WHERE id = $1', [faultId]);
      if (!check.rows[0]) return res.status(404).json({ error: 'faultId does not reference an existing fault record.' });
    }

    const { rows } = await pool.query(
      `INSERT INTO fault_history (user_id, fault_id, query_message, query_model, query_ata, query_severity, note)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [req.user.id, faultId || null, queryMessage || null, queryModel || null, queryAta || null, querySeverity || null, note || null]
    );

    res.status(201).json({ history: rows[0] });
  })
);

historyRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 25, 1), 100);
    const offset = (page - 1) * limit;

    const { rows } = await pool.query(
      `SELECT h.*, af.message_code, af.severity, af.aircraft_model AS fault_model
       FROM fault_history h
       LEFT JOIN aircraft_faults af ON af.id = h.fault_id
       WHERE h.user_id = $1
       ORDER BY h.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );

    const countRes = await pool.query('SELECT COUNT(*)::int AS n FROM fault_history WHERE user_id = $1', [req.user.id]);

    res.json({ history: rows, pagination: { page, limit, total: countRes.rows[0].n } });
  })
);

historyRouter.delete(
  '/:id',
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      'DELETE FROM fault_history WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'History entry not found.' });
    res.json({ message: 'History entry deleted.' });
  })
);

app.use('/api/v1/history', historyRouter);

// -----------------------------------------------------------------------
// PDF EXPORT — /api/v1/export/pdf/:faultId  (requires auth)
// -----------------------------------------------------------------------
app.get(
  '/api/v1/export/pdf/:faultId',
  authRequired,
  asyncHandler(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT af.*, ac.name AS ata_chapter_name
       FROM aircraft_faults af
       LEFT JOIN ata_chapters ac ON ac.code = af.ata_chapter_code
       WHERE af.id = $1`,
      [req.params.faultId]
    );
    const fault = rows[0];
    if (!fault) return res.status(404).json({ error: 'Fault record not found.' });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="AFIA-${fault.message_code.replace(/\s+/g, '-')}.pdf"`);

    const doc = new PDFDocument({ margin: 50 });
    doc.pipe(res);

    doc.fontSize(20).fillColor('#0B1424').text('AFIA — Fault Report', { align: 'left' });
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor('#6B7A94').text(`Generated ${new Date().toLocaleString()} for ${req.user.full_name}`);
    doc.moveDown();

    doc.fontSize(14).fillColor('#0B1424').text(`${fault.message_code}  (${fault.message_system})`);
    doc.fontSize(11).fillColor('#1E9FE8').text(
      `${fault.aircraft_model} · ATA ${fault.ata_chapter_code || '—'} ${fault.ata_chapter_name || ''} · Severity: ${fault.severity}`
    );
    doc.moveDown();

    doc.fontSize(12).fillColor('#0B1424').text('Explanation', { underline: true });
    doc.fontSize(11).fillColor('#12203E').text(fault.explanation);
    doc.moveDown();

    doc.fontSize(12).fillColor('#0B1424').text('Probable Causes', { underline: true });
    (fault.probable_causes || []).forEach((c) => doc.fontSize(11).fillColor('#12203E').text(`• ${c}`));
    doc.moveDown();

    doc.fontSize(12).fillColor('#0B1424').text('Maintenance Actions', { underline: true });
    (fault.maintenance_actions || []).forEach((a) => doc.fontSize(11).fillColor('#12203E').text(`• ${a}`));
    doc.moveDown();

    if (fault.reference_notes && fault.reference_notes.length) {
      doc.fontSize(12).fillColor('#0B1424').text('Reference Notes', { underline: true });
      fault.reference_notes.forEach((r) => doc.fontSize(10).fillColor('#6B7A94').text(`• ${r}`));
      doc.moveDown();
    }

    doc.fontSize(9).fillColor('#6B7A94').text(
      'For training and reference use only. This report does not replace official AMM/FIM/TSM procedures or certified maintenance data.',
      { align: 'left' }
    );

    doc.end();
  })
);

// -----------------------------------------------------------------------
// 404 + error handling
// -----------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed by CORS policy.' });
  }
  res.status(err.status || 500).json({ error: err.message || 'Internal server error.' });
});

// -----------------------------------------------------------------------
// Boot
// -----------------------------------------------------------------------
async function start() {
  try {
    await ensureSchema();
    await seedIfEmpty();
    app.listen(PORT, () => {
      console.log(`AFIA API listening on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start AFIA API:', err);
    process.exit(1);
  }
}

start();

module.exports = app;
