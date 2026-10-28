import type {
  AssuranceLane,
  DefenseMode,
  Digest,
  Epoch,
  FeedbackProfile,
  InteractionMode,
  PreflightCheck,
  PreflightReport,
} from '../../lib/schemas';

export interface SetupFormData {
  // Step 1: Domain & Epoch
  domain: string;
  epoch: number | string; // user input can temporarily be a string or invalid type before validation

  // Step 2: Target Inference
  target_model: string;
  inference_engine: string;
  target_deadline_ms: number;
  output_max_tokens: number;

  // Step 3: Blue Defense & Mode (MEM-003 §2a)
  defense_image_digest: string;
  defense_mode: DefenseMode;
  defense_deadline_ms: number;
  readonly prefix_cache_salt: 'server-assigned secret [embargoed]';

  // Step 4: Red Constraints, Assurance Lane & Datasets (MEM-004 §11)
  body_max_bytes: number;
  text_max_bytes: number;
  queue_depth: number;
  assurance_lane: AssuranceLane;
  dataset_catalog_id: string;

  // Step 5: Disclosure Policy & Interaction Mode (MEM-003 §2a)
  interaction_mode: InteractionMode;
  disclosure_policy: FeedbackProfile;
  budget_profile_id: string;
}

export type SetupFieldErrors = Partial<Record<keyof SetupFormData, string>>;

export interface ManifestDraftPayload {
  protocol_version: 'arena.v2';
  domain: string;
  epoch: Epoch;
  interaction_mode: InteractionMode;
  profile: FeedbackProfile;
  assurance_lane: AssuranceLane;
  dataset_catalog_id: string;
  budget_profile_id: string;
  target_inference: {
    model: string;
    engine: string;
    deadline_ms: number;
    output_max_tokens: number;
  };
  blue_defense: {
    image_digest: Digest | string;
    defense_mode: DefenseMode;
    deadline_ms: number;
    prefix_cache_salt: 'server-assigned secret [embargoed]';
  };
  red_constraints: {
    body_max_bytes: number;
    text_max_bytes: number;
    queue_depth: number;
  };
}

export interface SetupReceipt {
  receipt_id: string;
  experiment_id: string;
  manifest_digest: Digest;
  epoch: Epoch;
  domain: string;
  timestamp_utc: string;
  state: string;
}

export type { PreflightCheck, PreflightReport };
