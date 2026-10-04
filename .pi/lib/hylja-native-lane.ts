/**
 * Hylja native foreground lane controller: the Pi adapter for the opt-in controller.
 *
 * Developer tooling, not runtime core, not a security boundary, not a shell sandbox. It answers one
 * fixed input (`hylja-native-lane`) so root can run one foreground `pi-subagents` leaf through the
 * documented structured delegation API without a coordinator-model turn. Every other input is also
 * handled here and refused, so no operator input can reach a parent model, and no import, setup,
 * settlement, receipt or dispatch-write error escapes: this handler always returns `handled`.
 *
 * Before it emits anything the controller resolves the exported `resolveSubagentLaunchContract` from
 * the exact installed package directory, for the same task, cwd, fresh context, parent model
 * registry and bridge input the request carries. It persists the canonical expected launch digest and
 * the declared guard identity with the exact dispatch tuple, and only then emits the request, so
 * root can cancel exactly this owned leaf and so the terminal record can be compared against a
 * contract that is bound to this dispatch rather than to any intent.
 *
 * Bounded by construction: the only fields this file writes are the identity tuple, the launch
 * expectation, status, model, elapsed milliseconds, tool count and the leaf's own literal public
 * result. `recentOutput`, `currentToolArgs`, `recentTools`, raw session transcripts and provider
 * reasoning are never read.
 *
 * A root may configure one optional `softBudgetMs`, strictly below the finite hard `timeoutMs`. It
 * adds exactly two things: a numeric soft/hard timing paragraph to the child's own initial task, and
 * one bounded `soft_budget_reached` progress snapshot at the soft budget. That snapshot is a warning
 * for root and the progress file only: it is pinned inside both halves of the progress window, so the
 * leaf's own later updates cannot push it out of the tail root reads after the child exits. It is
 * never delivered to the running child, and it never cancels, kills, deletes, resets or approves
 * anything. Without it the lane behaves exactly as before and arms no timer.
 *
 * A root may also configure one optional bounded `requiredReferences` list: simple labels paired with
 * absolute paths the lane is expected to be able to read. It is a structured declaration, never prose
 * that is parsed or guessed, and there is no search for a replacement when a path is wrong. Every
 * entry is admitted by file metadata alone - an existing regular file this process can open for
 * reading, contents never read - before the launch contract is resolved and before any request is
 * emitted, so a missing, relative, wrong-shaped, directory, unreadable or overbound entry is the fixed
 * setup refusal with zero dispatch. Admission is exactly that: not approval, and no promise that the
 * path still exists or is still readable when the leaf reads it. Admitted labels and exact paths are
 * rendered once into the same effective task the launch contract is resolved for, inside the existing
 * raw task cap. Omitting the list keeps the previous behaviour exactly, with no probe and no paragraph.
 */

import { randomUUID } from 'node:crypto';
import { closeSync, openSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { clearTimeout as cancelTimer, setTimeout as startTimer } from 'node:timers';
import { pathToFileURL } from 'node:url';

/** The one input this controller runs a lane for. */
export const FIXED_LANE_INPUT = 'hylja-native-lane';

/** Root-supplied lane config path. Exact operator path, never searched for. */
export const LANE_CONFIG_ENV = 'HYLJA_NATIVE_LANE_CONFIG';

/** Root-supplied exact installed `pi-subagents` package directory, never a machine-wide discovery. */
export const LANE_SUBAGENTS_ENV = 'HYLJA_NATIVE_LANE_SUBAGENTS';

export const LANE_ROLES = ['hylja-implementer', 'hylja-reviewer'];

/** The only verdict tokens this file will read out of a leaf result. Anything else is INCOMPLETE. */
export const LANE_VERDICTS = ['APPROVED', 'CHANGES REQUESTED', 'INCOMPLETE'];

/** Hard cap on persisted progress records. The file is rewritten, never appended without bound. */
export const MAX_PROGRESS_RECORDS = 256;

/**
 * Hard cap on the serialized UTF-8 bytes the persisted progress file may occupy. This is the same
 * window the CLI reader parses its tail through, so a record this writer retains is a record the
 * reader can actually see: the record cap and this byte cap are two halves of one end-to-end
 * contract, not two independent caps that happen to disagree. The CLI imports this exact constant
 * rather than deriving a second number that could drift from the writer's.
 */
export const MAX_PROGRESS_BYTES = MAX_PROGRESS_RECORDS * 512;

/** The raw cap on one task, and the cap the effective task must also stay inside. */
export const MAX_TASK_CHARS = 1_048_576;

/** Bounds on one optional required-reference list. They are admission bounds, not parsing bounds. */
export const MAX_REQUIRED_REFERENCES = 16;
export const MAX_REFERENCE_LABEL_CHARS = 128;
export const MAX_REFERENCE_PATH_CHARS = 4096;

/**
 * The one bridge value used for both the preflight and the request it is compared against: a lane leaf
 * has no supervisor session to answer it, and a mismatched pair would make digests incomparable.
 */
export const LANE_BRIDGE_INPUT = { mode: 'off' } as const;

/** Fixed, non-echoing setup failures. A planted config or event value is never returned. */
export const SETUP_FAILURES = {
	config: 'SETUP_FAILED_LANE_CONFIG',
	modules: 'SETUP_FAILED_MODULE_RESOLUTION',
	contract: 'SETUP_FAILED_LAUNCH_CONTRACT',
	references: 'SETUP_FAILED_REQUIRED_REFERENCE',
	dispatch: 'SETUP_FAILED_DISPATCH_PERSIST',
	progress: 'SETUP_FAILED_PROGRESS_WRITE',
	receipt: 'SETUP_FAILED_RECEIPT_WRITE',
	settlement: 'SETUP_FAILED_SETTLEMENT',
} as const;

export type LaneSetupFailure = (typeof SETUP_FAILURES)[keyof typeof SETUP_FAILURES];
export type LaneVerdict = (typeof LANE_VERDICTS)[number];

/** One declared reference: a simple label root chose and the exact absolute path it named. */
export interface LaneRequiredReference {
	readonly label: string;
	readonly path: string;
}

export interface LaneConfig {
	readonly key: string;
	readonly agent: string;
	readonly task: string;
	readonly cwd: string;
	readonly timeoutMs: number;
	/** Optional soft budget. Absent means no warning timer and no timing guide. */
	readonly softBudgetMs?: number;
	/** Optional required references. Absent means no probe, no refusal and no rendered block. */
	readonly requiredReferences?: readonly LaneRequiredReference[];
	readonly sessionDir: string;
	readonly receipt: string;
	readonly dispatch: string;
	readonly progress: string;
	readonly guard: string;
}

/** What one metadata probe may report about a declared path. Nothing else about the file is read. */
export interface LaneReferenceMetadata {
	readonly isFile: boolean;
	readonly isDirectory: boolean;
	readonly readable: boolean;
}

/**
 * One bounded filesystem view over a declared path. `null` means no such readable metadata was
 * obtained: absent, a broken link, a denied path component, or a seam that could not answer at all.
 */
export type LaneReferenceProbe = (path: string) => LaneReferenceMetadata | null;

/** The narrow host surface this adapter uses. Nothing else about Pi is read. */
export interface LaneEventBus {
	on(event: string, handler: (payload: unknown) => void): () => void;
	emit(event: string, payload: unknown): void;
}

export interface LanePiHost {
	readonly events: LaneEventBus;
	on(event: string, handler: (payload: unknown) => unknown): void;
	readonly modelRegistry?: { getAvailable?: () => unknown };
}

/** The documented event-name constants, narrowed to the five this adapter subscribes to. */
export interface LaneDelegationModule {
	readonly SUBAGENT_DELEGATION_REQUEST_EVENT: string;
	readonly SUBAGENT_DELEGATION_STARTED_EVENT: string;
	readonly SUBAGENT_DELEGATION_UPDATE_EVENT: string;
	readonly SUBAGENT_DELEGATION_RESPONSE_EVENT: string;
	readonly SUBAGENT_DELEGATION_CANCEL_EVENT: string;
}

export interface LanePreflightContract {
	readonly context: string;
	readonly model?: string;
	readonly thinking?: string;
	readonly roots: { readonly cwd: string };
	readonly tools: {
		readonly configuredExtensions: readonly string[];
		readonly runtimeExtensions: readonly string[];
		readonly disableAmbientExtensions: boolean;
	};
	readonly launchContractDigest: string;
}

export type LanePreflightResult =
	| { ok: true; contract: LanePreflightContract }
	| { ok: false; code: string; message: string };

export interface LanePreflightModule {
	resolveSubagentLaunchContract(input: Record<string, unknown>): Promise<LanePreflightResult>;
}

export interface LaneModules {
	readonly delegation: LaneDelegationModule;
	readonly preflight: LanePreflightModule;
}

/** The launch contract this dispatch is bound to. Persisted before the request is emitted. */
export interface LaneExpectation {
	readonly launchContractDigest: string;
	readonly guardExtension: string;
	readonly configuredExtensions: readonly string[];
	readonly runtimeExtensions: readonly string[];
	readonly disableAmbientExtensions: boolean;
	readonly context: string;
	readonly cwd: string;
	readonly model: string;
	readonly thinking: string | null;
}

export interface LaneDispatchRecord {
	readonly requestId: string;
	readonly ownerRunId: string;
	readonly nodeId: string;
	readonly agent: string;
	readonly pid: number;
	readonly timeoutMs: number;
	readonly expected: LaneExpectation;
}

export interface LaneTuple {
	readonly requestId: string;
	readonly ownerRunId: string;
	readonly nodeId: string;
}

export interface LaneProgressRecord {
	event: string;
	key: string;
	model?: string;
	runId?: string;
	toolCount?: number;
	elapsedMs?: number;
}

export interface LaneTerminalReceipt {
	readonly requestId: string | null;
	readonly ownerRunId: string | null;
	readonly nodeId: string | null;
	readonly status: string;
	readonly runId: string | null;
	readonly agent: string;
	readonly model: string | null;
	readonly thinking: string | null;
	readonly exitCode: number | null;
	readonly launchContractDigest: string | null;
	readonly usage: Record<string, number> | null;
	readonly verdict: LaneVerdict;
	readonly result: { readonly kind: 'text'; readonly text: string } | null;
}

export interface LaneControllerDeps {
	readonly addSignalListener?: (name: string, handler: () => void) => () => void;
	readonly now?: () => number;
	/** Arms one bounded warning timer and returns the closure that cancels exactly that timer. */
	readonly arm?: (handler: () => void, delayMs: number) => () => void;
	/**
	 * The metadata view over declared reference paths. Injected so an unreadable reference is provable
	 * by fault injection rather than by permission bits a root process does not honour anyway.
	 */
	readonly referenceProbe?: LaneReferenceProbe;
}

export interface LaneController {
	readonly request: Record<string, unknown>;
	readonly tuple: LaneTuple;
	readonly expectation: LaneExpectation | null;
	readonly setupFailure: LaneSetupFailure | null;
	cancel(): boolean;
	settle(): Promise<unknown>;
}

const isSetupFailure = (value: string): value is LaneSetupFailure =>
	(Object.values(SETUP_FAILURES) as readonly string[]).includes(value);

const isBoolean = (value: unknown): value is boolean => typeof value === 'boolean';

const isText = (value: unknown): value is string => typeof value === 'string';
const isBoundedText = (value: unknown): value is string => isText(value) && value.length > 0 && value.length <= 4096;
const isCount = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const record = (value: unknown): Record<string, unknown> | null =>
	(typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null) as Record<string, unknown> | null;

/**
 * A label is short text with no control character, so a rendered line cannot be forged by a label.
 * A path is absolute, bounded, and NUL-free: exactly what the operator declared, never resolved or
 * searched for. Nothing here is inferred from the task prose.
 */
const isSimpleLabel = (value: unknown): value is string =>
	isText(value)
	&& value.length <= MAX_REFERENCE_LABEL_CHARS
	&& !Array.from(value).some((char) => {
		const code = char.codePointAt(0) ?? 0;
		return code < 0x20 || code === 0x7f;
	});

const isReferencePath = (value: unknown): value is string =>
	isText(value) && value.length <= MAX_REFERENCE_PATH_CHARS && value.startsWith('/') && !value.includes('\0');

/**
 * Parses the one optional structured list. Absent stays absent and an empty list asserts no
 * references. Every other shape - a bare path string, a label-to-path map, a primitive entry, an
 * unknown field, a relative or overbound path, a control character in a label, or more entries than
 * the bound - is the fixed reference refusal. No planted label, path or entry is ever returned.
 */
function parseRequiredReferences(value: unknown): readonly LaneRequiredReference[] | null {
	if (value === undefined) return null;
	if (!Array.isArray(value) || value.length > MAX_REQUIRED_REFERENCES) throw new Error(SETUP_FAILURES.references);
	const references: LaneRequiredReference[] = [];
	for (const entry of value) {
		const fields = record(entry);
		// Exactly the two declared fields. An extra field is refused rather than rendered or ignored.
		if (fields === null || Object.keys(fields).length !== 2) throw new Error(SETUP_FAILURES.references);
		if (!isSimpleLabel(fields.label) || !isReferencePath(fields.path)) throw new Error(SETUP_FAILURES.references);
		references.push({ label: fields.label, path: fields.path });
	}
	return references;
}

export type LaneReferenceList =
	| { readonly ok: true; readonly references: readonly LaneRequiredReference[] | null }
	| { readonly ok: false };

/** The shape check both readers share, so a config the CLI admits is one the controller admits. */
export function checkRequiredReferenceList(value: unknown): LaneReferenceList {
	try {
		return { ok: true, references: parseRequiredReferences(value) };
	} catch {
		return { ok: false };
	}
}

/**
 * The shipped probe: stat metadata plus one open-for-read that is closed immediately and reads
 * nothing. A process that bypasses file permissions admits exactly what it can actually open, which
 * is the honest answer for the process that will read the path later.
 */
export const probeReferenceMetadata: LaneReferenceProbe = (path) => {
	try {
		const stats = statSync(path);
		let readable = false;
		try {
			closeSync(openSync(path, 'r'));
			readable = true;
		} catch {
			readable = false;
		}
		return { isFile: stats.isFile(), isDirectory: stats.isDirectory(), readable };
	} catch {
		// No readable metadata at all: absent, a broken link, or a denied path component. The
		// underlying error text never leaves this adapter.
		return null;
	}
};

/**
 * Admits declared references by metadata alone: each path must be an existing regular file this
 * process can open for reading. Contents are never read, no path is resolved, searched for or
 * substituted, and admission is neither approval nor a promise about later availability.
 */
export function admitRequiredReferences(references: readonly LaneRequiredReference[], probe: LaneReferenceProbe): void {
	for (const reference of references) {
		let probed: unknown = null;
		try {
			probed = probe(reference.path);
		} catch {
			throw new Error(SETUP_FAILURES.references);
		}
		const metadata = record(probed);
		if (
			metadata === null
			|| !isBoolean(metadata.isFile)
			|| !isBoolean(metadata.isDirectory)
			|| !isBoolean(metadata.readable)
			|| metadata.isFile !== true
			|| metadata.isDirectory !== false
			|| metadata.readable !== true
		) {
			throw new Error(SETUP_FAILURES.references);
		}
	}
}

/** Reads and validates the subset of the root-owned lane config this controller owns. */
export function readLaneConfig(path: string): LaneConfig {
	let raw: unknown;
	try {
		raw = JSON.parse(readFileSync(path, 'utf8'));
	} catch {
		throw new Error(SETUP_FAILURES.config);
	}
	const value = record(raw);
	if (value === null) throw new Error(SETUP_FAILURES.config);
	const text = (field: string): string => {
		const entry = value[field];
		if (!isText(entry) || entry.length === 0) throw new Error(SETUP_FAILURES.config);
		return entry;
	};
	if (typeof value.agent !== 'string' || !LANE_ROLES.includes(value.agent)) throw new Error(SETUP_FAILURES.config);
	const key = text('key');
	if (key.length > 128) throw new Error(SETUP_FAILURES.config);
	const task = text('task');
	if (task.length > MAX_TASK_CHARS) throw new Error(SETUP_FAILURES.config);
	// Optional required references: a declaration root owns, never inferred from the task prose.
	const requiredReferences = parseRequiredReferences(value.requiredReferences);
	if (!isCount(value.timeoutMs) || !Number.isInteger(value.timeoutMs)) throw new Error(SETUP_FAILURES.config);
	// Optional soft budget. Present means a positive integer strictly below the finite hard timeout;
	// anything else is the fixed config refusal. Absent keeps the previous behaviour exactly.
	let softBudgetMs: number | undefined;
	if ('softBudgetMs' in value) {
		const soft = value.softBudgetMs;
		if (typeof soft !== 'number' || !Number.isInteger(soft) || soft <= 0 || soft >= value.timeoutMs) throw new Error(SETUP_FAILURES.config);
		softBudgetMs = soft;
	}
	if (typeof value.pid !== 'undefined') throw new Error(SETUP_FAILURES.config);
	const paths = {} as Record<'cwd' | 'sessionDir' | 'receipt' | 'dispatch' | 'progress' | 'guard', string>;
	for (const field of ['cwd', 'sessionDir', 'receipt', 'dispatch', 'progress', 'guard'] as const) {
		const entry = text(field);
		if (!entry.startsWith('/')) throw new Error(SETUP_FAILURES.config);
		paths[field] = entry;
	}
	return {
		key,
		agent: value.agent,
		task,
		timeoutMs: value.timeoutMs,
		...(softBudgetMs === undefined ? {} : { softBudgetMs }),
		...(requiredReferences === null || requiredReferences.length === 0 ? {} : { requiredReferences }),
		...paths,
	};
}

/**
 * The one paragraph a configured soft budget adds to the child's task: the two numbers it will be
 * measured against, that role's own closing move, and an explicit statement that the guide carries no
 * authority the role body does not already have. An unconfigured lane gets its task back unchanged.
 */
const TIMING_GUIDE: Record<string, string> = {
	'hylja-implementer': 'Finish the scoped checks, commit the scoped paths, then report.',
	'hylja-reviewer': 'Report one literal verdict line (APPROVED, CHANGES REQUESTED or INCOMPLETE) and stay read-only.',
};

/**
 * The one paragraph declared references add to the child's task: what admission actually was, what it
 * is not, and what to do when a path is gone. Labels and exact paths are rendered once, here, and
 * nowhere else; there is no alternative search and no substitute file.
 */
const REFERENCE_GUIDE = 'Root checked each exact path below before launching this lane and admitted it by'
	+ ' file metadata only. That admission is not approval, and it does not guarantee the path still exists'
	+ ' or is still readable when you read it. Read each path exactly as written and never substitute another'
	+ ' file for it; if one is gone, report INCOMPLETE and name which.';

/**
 * The exact string the launch contract is resolved for and the exact string that is dispatched, with
 * the declared references and the optional timing guide appended to the raw task. The raw cap still
 * binds the result: an effective task past the cap fails restrictively instead of losing its tail,
 * because a truncated task would dispatch a leaf whose digest covers different bytes than the task it
 * was given. Omitting both optional sections returns the raw task byte for byte.
 */
export function buildEffectiveTask(config: LaneConfig): string {
	const references = config.requiredReferences ?? [];
	const sections = [config.task];
	if (references.length > 0) {
		sections.push(`[Required references] ${REFERENCE_GUIDE}\n`
			+ references.map((reference) => `- ${reference.label}: ${reference.path}`).join('\n'));
	}
	if (config.softBudgetMs !== undefined) {
		const role = TIMING_GUIDE[config.agent];
		if (role === undefined) throw new Error(SETUP_FAILURES.config);
		sections.push(`[Lane timing] Soft budget ${config.softBudgetMs} ms, hard deadline ${config.timeoutMs} ms,`
			+ ' both counted from dispatch. Root is warned once at the soft budget; that warning is not sent to you,'
			+ ' cancels nothing and approves nothing. '
			+ `${role} This guide grants no authority beyond your role body.`);
	}
	const effective = sections.join('\n\n');
	if (effective.length > MAX_TASK_CHARS) throw new Error(SETUP_FAILURES.config);
	return effective;
}

/**
 * Resolves the exported `pi-subagents/delegation` and `pi-subagents/preflight` entrypoints from the
 * exact installed package directory through that package's own export map. No path is guessed, so a
 * resolved module can never land outside the package the operator declared.
 */
export function resolveInstalledModules(packageDir: string): { delegationUrl: string; preflightUrl: string } {
	try {
		if (!isText(packageDir) || !packageDir.startsWith('/')) throw new Error(SETUP_FAILURES.modules);
		const requireFrom = createRequire(`${packageDir}/package.json`);
		const delegationUrl = pathToFileURL(requireFrom.resolve('pi-subagents/delegation')).href;
		const preflightUrl = pathToFileURL(requireFrom.resolve('pi-subagents/preflight')).href;
		if (!delegationUrl.startsWith(pathToFileURL(`${packageDir}/`).href) || !preflightUrl.startsWith(pathToFileURL(`${packageDir}/`).href)) {
			throw new Error(SETUP_FAILURES.modules);
		}
		return { delegationUrl, preflightUrl };
	} catch {
		// Fixed, non-echoing failure: an unresolved package path never returns its own error text.
		throw new Error(SETUP_FAILURES.modules);
	}
}

/** The leaf's literal first line, only when it is exactly one of the three declared verdicts. */
export function readExplicitVerdict(text: unknown): LaneVerdict {
	const first = isText(text) ? text.split('\n', 1)[0]?.trim() : undefined;
	return first !== undefined && (LANE_VERDICTS as readonly string[]).includes(first) ? (first as LaneVerdict) : 'INCOMPLETE';
}

/** Finite non-negative counters only, so a progress record can never carry a string or a NaN. */
function readCount(value: unknown): number | null {
	return isCount(value) ? value : null;
}

/** The one warning snapshot a configured soft budget adds, and the one record the cap retains. */
const SOFT_BUDGET_EVENT = 'soft_budget_reached';

/** One UTF-8 encoder for the serialized size of the exact bytes the progress file carries. */
const UTF8 = new TextEncoder();

/**
 * The serialized cost of one progress line inside the file: its UTF-8 bytes plus the one newline that
 * separates it from the next. N such lines, joined and terminated, are exactly the sum of their costs,
 * so this is the file's size and not an estimate of it. Measured after JSON escaping and in UTF-8,
 * because that is what is persisted and what the reader's bounded positional read counts.
 */
const progressLineBytes = (line: string): number => UTF8.encode(line).length + 1;

/**
 * The bounded tail this writer persists: inside the record cap and the byte window at the same time,
 * so a record the writer retains is a record the reader's own window can still reach. Retention at
 * the writer is only meaningful if it implies availability at the reader, and a record count alone
 * never established that: a leaf whose accepted metadata is long fills the byte window long before it
 * fills the record cap, which drops the records root reads after exit without ever writing past the
 * count cap. The one soft warning is pinned inside that window and the newest ordinary updates fill
 * what it leaves, oldest survivor first; when the window binds, ordinary records are what is evicted.
 */
function retainedProgress(records: readonly LaneProgressRecord[]): LaneProgressRecord[] {
	// The newest ordinary updates fill the window first, against the count cap and the byte cap at the
	// same time, so the survivors are one chronological tail rather than two independently chosen sets.
	const windowed = records.slice(-MAX_PROGRESS_RECORDS);
	let used = 0;
	const kept: LaneProgressRecord[] = [];
	for (let index = windowed.length - 1; index >= 0; index -= 1) {
		const item = windowed[index];
		if (item === undefined) break;
		const cost = progressLineBytes(JSON.stringify(item));
		// The newest update is never the one dropped: every persisted field is bounded far below the
		// window, so one record always fits it. Everything older stops at the first that no longer does.
		if (kept.length > 0 && used + cost > MAX_PROGRESS_BYTES) break;
		kept.unshift(item);
		used += cost;
	}
	// The warning is looked for across the whole history and not only this tail, because the leaf's own
	// later updates are exactly what can have pushed it out of the window. It joins as the oldest
	// survivor and the ordinary records it displaces are dropped from the oldest end, so pinning it
	// costs the window neither a record nor a byte it was already allowed to keep.
	const warned = records.find((item) => item.event === SOFT_BUDGET_EVENT);
	if (warned === undefined || kept.includes(warned)) return kept;
	kept.unshift(warned);
	used += progressLineBytes(JSON.stringify(warned));
	// `used` stays the exact file size here: the sum of the kept records' serialized costs.
	while (kept.length > 1 && (kept.length > MAX_PROGRESS_RECORDS || used > MAX_PROGRESS_BYTES)) {
		const dropped = kept.splice(1, 1)[0];
		used -= dropped === undefined ? 0 : progressLineBytes(JSON.stringify(dropped));
	}
	return kept;
}

/**
 * Persists inside both halves of the one progress window: at most `MAX_PROGRESS_RECORDS` records and
 * at most `MAX_PROGRESS_BYTES` serialized UTF-8 bytes. The file is rewritten, never appended.
 */
function pushProgress(path: string, key: string, records: LaneProgressRecord[], entry: LaneProgressRecord): void {
	records.push(entry);
	const kept = retainedProgress(records);
	records.length = 0;
	records.push(...kept);
	writeFileSync(path, `${kept.map((item) => JSON.stringify(item)).join('\n')}\n`, { mode: 0o600 });
}

function writeJson(path: string, value: unknown): void {
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

/** Writes the public terminal receipt: literal public result plus authoritative usage and identity. */
export function writeTerminalReceipt(config: LaneConfig, value: unknown): LaneTerminalReceipt {
	const payload = record(value);
	const result = record(payload?.result);
	const usage = record(payload?.usage);
	const numericUsage: Record<string, number> = {};
	for (const [field, entry] of Object.entries(usage ?? {})) {
		const count = readCount(entry);
		if (count !== null) numericUsage[field] = count;
	}
	const text = result?.kind === 'text' && isText(result.text) ? result.text : null;
	const receipt: LaneTerminalReceipt = {
		requestId: isBoundedText(payload?.requestId) ? payload.requestId : null,
		ownerRunId: isBoundedText(payload?.ownerRunId) ? payload.ownerRunId : null,
		nodeId: isBoundedText(payload?.nodeId) ? payload.nodeId : null,
		status: isBoundedText(payload?.status) ? payload.status : 'unavailable',
		runId: isBoundedText(payload?.runId) ? payload.runId : null,
		agent: isBoundedText(payload?.agent) ? payload.agent : config.agent,
		model: isBoundedText(payload?.model) ? payload.model : null,
		thinking: isBoundedText(payload?.thinking) ? payload.thinking : null,
		exitCode: readCount(payload?.exitCode),
		launchContractDigest: isBoundedText(payload?.launchContractDigest) ? payload.launchContractDigest : null,
		usage: Object.keys(numericUsage).length === 0 ? null : numericUsage,
		// Completed means completed: a completed leaf is never approval, so the verdict is only the
		// leaf's own literal verdict line, and INCOMPLETE when it declares none.
		verdict: text === null ? 'INCOMPLETE' : readExplicitVerdict(text),
		result: text === null ? null : { kind: 'text', text },
	};
	writeJson(config.receipt, receipt);
	return receipt;
}

/** The same exact tuple on every event: a foreign attempt never settles, cancels or reports here. */
const ownsTuple = (value: unknown, tuple: LaneTuple): boolean => {
	const payload = record(value);
	return payload?.requestId === tuple.requestId
		&& payload?.ownerRunId === tuple.ownerRunId
		&& payload?.nodeId === tuple.nodeId;
};

/**
 * Resolves the launch contract for this dispatch and keeps only the fields root later verifies.
 * Nothing is inferred: an unresolved contract, an unbound model or a guard outside the resolved
 * configured set is a setup failure, and no request is emitted.
 */
async function resolveExpectation(
	pi: LanePiHost,
	config: LaneConfig,
	effectiveTask: string,
	preflight: LanePreflightModule,
): Promise<LaneExpectation> {
	const availableModels = typeof pi.modelRegistry?.getAvailable === 'function' ? pi.modelRegistry.getAvailable() : undefined;
	const result = await preflight.resolveSubagentLaunchContract({
		agent: config.agent,
		task: effectiveTask,
		context: 'fresh',
		cwd: config.cwd,
		sessionRoot: config.sessionDir,
		intercomBridge: LANE_BRIDGE_INPUT,
		runtimeSnapshotHost: pi,
		...(Array.isArray(availableModels) ? { availableModels } : {}),
	});
	if (result === null || result.ok !== true) throw new Error(SETUP_FAILURES.contract);
	const contract = result.contract;
	const tools = record(contract?.tools);
	const configured = Array.isArray(tools?.configuredExtensions) ? tools.configuredExtensions.filter(isText) : [];
	if (
		!isBoundedText(contract?.launchContractDigest)
		|| contract.context !== 'fresh'
		|| contract.roots?.cwd !== config.cwd
		|| !isBoundedText(contract.model)
		|| tools?.disableAmbientExtensions !== true
		|| configured.length === 0
		|| !configured.includes(config.guard)
	) {
		throw new Error(SETUP_FAILURES.contract);
	}
	return {
		launchContractDigest: contract.launchContractDigest,
		guardExtension: config.guard,
		configuredExtensions: configured,
		runtimeExtensions: Array.isArray(tools.runtimeExtensions) ? tools.runtimeExtensions.filter(isText) : [],
		disableAmbientExtensions: true,
		context: 'fresh',
		cwd: config.cwd,
		model: contract.model,
		thinking: isBoundedText(contract.thinking) ? contract.thinking : null,
	};
}

/**
 * The controller body. `pi` is the host event API and `modules` carries the installed delegation and
 * preflight exports. Every export is settled before the request is emitted, so a root-owned dispatch
 * tuple always exists for the leaf that was actually launched.
 */
export async function createLaneController(
	pi: LanePiHost,
	config: LaneConfig,
	modules: LaneModules,
	deps: LaneControllerDeps = {},
): Promise<LaneController> {
	const addSignalListener = deps.addSignalListener ?? defaultSignalListener;
	const now = deps.now ?? (() => Date.now());
	const arm = deps.arm ?? defaultArm;
	const referenceProbe = deps.referenceProbe ?? probeReferenceMetadata;
	const request: Record<string, unknown> = {
		requestId: randomUUID(),
		ownerRunId: randomUUID(),
		nodeId: config.key,
		agent: config.agent,
		task: config.task,
		context: 'fresh',
		cwd: config.cwd,
		timeoutMs: config.timeoutMs,
		intercomBridge: LANE_BRIDGE_INPUT,
		result: { kind: 'text' },
	};
	const tuple: LaneTuple = {
		requestId: request.requestId as string,
		ownerRunId: request.ownerRunId as string,
		nodeId: config.key,
	};
	const startedAt = now();
	const records: LaneProgressRecord[] = [];
	let settled = false;
	let cancelled = false;
	let warned = false;
	let expectation: LaneExpectation | null = null;
	let setupFailure: LaneSetupFailure | null = null;
	const offs: Array<() => void> = [];
	/** Everything this lane owns and must drain: the two signal hooks and any armed warning timer. */
	const cleanups: Array<() => void> = [];

	/** Bounded progress: an event token, the lane key, a model and runId string, finite counters. */
	const progress = (event: string, fields: {
		model?: unknown; runId?: unknown; toolCount?: unknown; elapsedMs?: unknown;
	} = {}): void => {
		const model = isBoundedText(fields.model) ? fields.model : null;
		const runId = isBoundedText(fields.runId) ? fields.runId : null;
		const toolCount = readCount(fields.toolCount);
		const elapsedMs = readCount(fields.elapsedMs) ?? readCount(now() - startedAt);
		try {
			pushProgress(config.progress, config.key, records, {
				event,
				key: config.key,
				...(model === null ? {} : { model }),
				...(runId === null ? {} : { runId }),
				...(toolCount === null ? {} : { toolCount }),
				...(elapsedMs === null ? {} : { elapsedMs }),
			});
		} catch {
			// A progress write failure never becomes a leaf: the lane is reported INCOMPLETE instead.
			setupFailure = setupFailure ?? SETUP_FAILURES.progress;
		}
	};

	// A setup failure settles the same way a terminal response does, so `settle()` can never leave a
	// caller waiting on an attempt that was never launched.
	let settleTerminal: (value: unknown) => void = () => undefined;
	const terminal = new Promise<unknown>((resolve) => {
		settleTerminal = resolve;
		offs.push(pi.events.on(modules.delegation.SUBAGENT_DELEGATION_RESPONSE_EVENT, (value) => {
			if (!ownsTuple(value, tuple)) return;
			resolve(value);
		}));
	});
	offs.push(pi.events.on(modules.delegation.SUBAGENT_DELEGATION_STARTED_EVENT, (value) => {
		if (ownsTuple(value, tuple)) progress('started', { model: record(value)?.model, runId: record(value)?.runId });
	}));
	offs.push(pi.events.on(modules.delegation.SUBAGENT_DELEGATION_UPDATE_EVENT, (value) => {
		// A bounded snapshot, replaced rather than merged. No tool name, arguments or recent output.
		const payload = record(value);
		if (payload === null || !ownsTuple(payload, tuple)) return;
		progress('progress', {
			model: payload.model,
			runId: payload.runId,
			toolCount: payload.toolCount,
			elapsedMs: payload.durationMs,
		});
	}));
	offs.push(pi.events.on(modules.delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, (value) => {
		if (ownsTuple(value, tuple)) progress('cancel_observed');
	}));

	const cancel = (): boolean => {
		if (settled || cancelled) return false;
		cancelled = true;
		pi.events.emit(modules.delegation.SUBAGENT_DELEGATION_CANCEL_EVENT, { ...tuple });
		progress('cancel_requested');
		return true;
	};

	const dispose = (): void => {
		for (const off of offs.splice(0)) {
			try {
				off();
			} catch {
				// A listener that refuses to drain cannot be retried; the lane is reported below.
			}
		}
		for (const off of cleanups.splice(0)) {
			try {
				off();
			} catch {
				// A cleanup that refuses to drain cannot be retried; the lane is reported below.
			}
		}
	};

	const controller: LaneController = {
		request,
		tuple,
		get expectation() {
			return expectation;
		},
		get setupFailure() {
			return setupFailure;
		},
		cancel,
		async settle(): Promise<unknown> {
			const value = await terminal;
			settled = true;
			dispose();
			return value;
		},
	};

	try {
		// One effective task, bound to both the launch contract and the dispatched request, so the
		// expected digest always covers exactly the bytes the child is given.
		const effectiveTask = buildEffectiveTask(config);
		request.task = effectiveTask;
		// Declared references are admitted before the launch contract is resolved and before anything
		// is persisted or emitted, so a broken one reaches no preflight, no child process and no
		// dispatch record. The probe is one bounded metadata read per declared path and no content.
		admitRequiredReferences(config.requiredReferences ?? [], referenceProbe);
		expectation = await resolveExpectation(pi, config, effectiveTask, modules.preflight);
		const dispatch: LaneDispatchRecord = {
			...tuple,
			agent: config.agent,
			pid: process.pid,
			timeoutMs: config.timeoutMs,
			expected: expectation,
		};
		writeJson(config.dispatch, dispatch);
		progress('dispatch', { model: expectation.model });
		cleanups.push(addSignalListener('SIGINT', cancel));
		cleanups.push(addSignalListener('SIGTERM', cancel));
		if (config.softBudgetMs !== undefined) {
			cleanups.push(arm(() => {
				// Root's warning and nothing more. The running child keeps only the numbers it was
				// given in its initial task: no cancel event, no kill, no deletion, no reset, and no
				// approval is produced here. One warning per dispatch, or none at all.
				if (warned || settled || cancelled || setupFailure !== null) return;
				warned = true;
				progress(SOFT_BUDGET_EVENT);
			}, config.softBudgetMs));
		}
		pi.events.emit(modules.delegation.SUBAGENT_DELEGATION_REQUEST_EVENT, request);
	} catch (error: unknown) {
		settled = true;
		dispose();
		const code = error instanceof Error && isSetupFailure(error.message) ? error.message : SETUP_FAILURES.dispatch;
		setupFailure = setupFailure ?? code;
		progress('setup_failure');
		settleTerminal(undefined);
	}
	return controller;
}

function defaultSignalListener(name: string, handler: () => void): () => void {
	const wrapped = (): void => {
		handler();
	};
	process.once(name, wrapped);
	return () => {
		process.removeListener(name, wrapped);
	};
}

/** The shipped arm: one real bounded timer, and the closure that cancels exactly that timer. */
function defaultArm(handler: () => void, delayMs: number): () => void {
	const timer = startTimer(handler, delayMs);
	return () => {
		cancelTimer(timer);
	};
}

/** The Pi entry point. Opt-in by an exact config path; project discovery never loads it. */
export function hyljaNativeLane(pi: LanePiHost): void {
	let started = false;
	pi.on('input', async (payload: unknown): Promise<{ action: string }> => {
		const text = record(payload)?.text;
		// Unexpected input is refused here, not forwarded: a parent-model turn is unreachable, and an
		// import, setup, settlement or write error is contained rather than escaped to the host.
		if (text !== FIXED_LANE_INPUT || started) return { action: 'handled' };
		started = true;
		try {
			const config = readLaneConfig(process.env[LANE_CONFIG_ENV] ?? '');
			const { delegationUrl, preflightUrl } = resolveInstalledModules(process.env[LANE_SUBAGENTS_ENV] ?? '');
			const [delegation, preflight] = await Promise.all([import(delegationUrl), import(preflightUrl)]);
			const controller = await createLaneController(pi, config, {
				delegation: delegation as unknown as LaneDelegationModule,
				preflight: preflight as unknown as LanePreflightModule,
			});
			if (controller.setupFailure !== null) {
				await controller.settle();
				return { action: 'handled' };
			}
			const value = await controller.settle();
			writeTerminalReceipt(config, value);
		} catch {
			// A setup failure, not a fallback: no dispatch, no leaf, no parent-model turn.
		}
		return { action: 'handled' };
	});
}

export default hyljaNativeLane;
