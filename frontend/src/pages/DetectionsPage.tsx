import { useState } from 'react'

import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  LoadingBlock,
  Modal,
  Mono,
  Pill,
  Select,
  SeverityBadge,
  Textarea,
} from '@/components/ui'
import { useToast } from '@/components/ui/toast'
import {
  useCreateIoc,
  useDetectionRules,
  useIocs,
  useUpdateDetectionRule,
  useUpdateIoc,
} from '@/hooks/queries'
import { ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { Permission, can } from '@/lib/permissions'
import { formatTimestamp, titleCase } from '@/lib/format'
import type { DetectionRule, IOCType } from '@/types/api'

function RuleRow({ rule, canManage }: { rule: DetectionRule; canManage: boolean }) {
  const toast = useToast()
  const update = useUpdateDetectionRule(rule.id)
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<Record<string, string>>(
    Object.fromEntries(Object.entries(rule.config).map(([key, value]) => [key, String(value)])),
  )

  const save = async () => {
    // Coerce back to the primitive types the rule's schema expects; the server
    // validates against that schema and rejects anything out of range.
    const config: Record<string, number | boolean> = {}
    for (const [key, value] of Object.entries(draft)) {
      if (value === 'true' || value === 'false') config[key] = value === 'true'
      else config[key] = Number(value)
    }
    try {
      await update.mutateAsync({ config })
      toast.push(`${rule.name} updated.`, 'success')
      setEditing(false)
    } catch (error) {
      toast.push(
        error instanceof ApiError ? error.message : 'Could not update the rule.',
        'error',
      )
    }
  }

  const isTuned = JSON.stringify(rule.config) !== JSON.stringify(rule.default_config)

  return (
    <li className="px-4 py-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-medium text-ink-100">{rule.name}</span>
            <SeverityBadge severity={rule.severity} />
            {rule.mitre_technique_id ? (
              <a
                href={`https://attack.mitre.org/techniques/${rule.mitre_technique_id.replace('.', '/')}/`}
                target="_blank"
                rel="noreferrer noopener"
                className="font-mono text-2xs text-accent hover:underline"
              >
                {rule.mitre_technique_id}
              </a>
            ) : null}
            {!rule.enabled ? <Pill>Disabled</Pill> : null}
            {isTuned ? <Pill>Tuned</Pill> : null}
            {!rule.implemented ? <Pill>No implementation</Pill> : null}
          </div>
          <p className="mt-1 text-2xs text-ink-300 max-w-2xl">{rule.description}</p>
          <p className="mt-1 text-2xs text-ink-400 font-mono">
            {Object.entries(rule.config)
              .map(([key, value]) => `${key}=${value}`)
              .join('  ')}
          </p>
        </div>

        {canManage ? (
          <div className="flex gap-1.5 shrink-0">
            <Button size="sm" onClick={() => setEditing(true)}>
              Tune
            </Button>
            <Button
              size="sm"
              variant={rule.enabled ? 'ghost' : 'primary'}
              disabled={update.isPending}
              onClick={async () => {
                await update.mutateAsync({ enabled: !rule.enabled })
                toast.push(
                  `${rule.name} ${rule.enabled ? 'disabled' : 'enabled'}.`,
                  'success',
                )
              }}
            >
              {rule.enabled ? 'Disable' : 'Enable'}
            </Button>
          </div>
        ) : null}
      </div>

      <Modal open={editing} title={`Tune ${rule.name}`} onClose={() => setEditing(false)}>
        <div className="space-y-3">
          <p className="text-2xs text-ink-400">
            Values are validated against the rule's own schema. An out-of-range threshold is
            rejected rather than stored, so a typo cannot silently disable a detection.
          </p>
          {Object.entries(rule.config).map(([key, value]) => (
            <div key={key}>
              <label htmlFor={`cfg-${rule.id}-${key}`} className="block text-2xs text-ink-300 mb-1">
                {titleCase(key)}{' '}
                <span className="text-ink-400">(default {String(rule.default_config[key])})</span>
              </label>
              {typeof value === 'boolean' ? (
                <Select
                  id={`cfg-${rule.id}-${key}`}
                  value={draft[key]}
                  onChange={(event) => setDraft({ ...draft, [key]: event.target.value })}
                >
                  <option value="true">true</option>
                  <option value="false">false</option>
                </Select>
              ) : (
                <Input
                  id={`cfg-${rule.id}-${key}`}
                  type="number"
                  value={draft[key]}
                  onChange={(event) => setDraft({ ...draft, [key]: event.target.value })}
                />
              )}
            </div>
          ))}
          <div className="flex justify-between gap-2">
            <Button
              onClick={() =>
                setDraft(
                  Object.fromEntries(
                    Object.entries(rule.default_config).map(([k, v]) => [k, String(v)]),
                  ),
                )
              }
            >
              Reset to defaults
            </Button>
            <div className="flex gap-2">
              <Button onClick={() => setEditing(false)}>Cancel</Button>
              <Button variant="primary" disabled={update.isPending} onClick={save}>
                Save
              </Button>
            </div>
          </div>
        </div>
      </Modal>
    </li>
  )
}

export default function DetectionsPage() {
  const { user } = useAuth()
  const toast = useToast()
  const rules = useDetectionRules()
  const iocs = useIocs({ page_size: 50 })
  const createIoc = useCreateIoc()

  const [adding, setAdding] = useState(false)
  const [iocType, setIocType] = useState<IOCType>('ip_address')
  const [value, setValue] = useState('')
  const [description, setDescription] = useState('')

  const canManageRules = can(user, Permission.DETECTION_MANAGE)
  const canManageIocs = can(user, Permission.IOC_MANAGE)

  const submitIoc = async () => {
    try {
      await createIoc.mutateAsync({ ioc_type: iocType, value, description })
      toast.push('Indicator added to the watchlist.', 'success')
      setAdding(false)
      setValue('')
      setDescription('')
    } catch (error) {
      toast.push(
        error instanceof ApiError ? error.message : 'Could not add the indicator.',
        'error',
      )
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-base font-semibold text-ink-100">Detection engineering</h1>
        <p className="mt-0.5 text-2xs text-ink-400">
          Rule logic lives in code and is version controlled. Thresholds are operational settings
          and are tuned here.
        </p>
      </div>

      <Card>
        <CardHeader
          title="Detection rules"
          subtitle={rules.data ? `${rules.data.length} rules` : undefined}
        />
        {rules.isLoading ? (
          <LoadingBlock />
        ) : rules.isError ? (
          <ErrorState message="Could not load rules." onRetry={() => rules.refetch()} />
        ) : rules.data?.length ? (
          <ul className="divide-y divide-surface-800">
            {rules.data.map((rule) => (
              <RuleRow key={rule.id} rule={rule} canManage={canManageRules} />
            ))}
          </ul>
        ) : (
          <EmptyState title="No detection rules registered" />
        )}
      </Card>

      <Card>
        <CardHeader
          title="Indicator watchlist"
          subtitle="Live detection input — adding an indicator affects the next event that matches"
          actions={
            canManageIocs ? (
              <Button size="sm" variant="primary" onClick={() => setAdding(true)}>
                Add indicator
              </Button>
            ) : null
          }
        />
        {iocs.isLoading ? (
          <LoadingBlock />
        ) : iocs.data?.items.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-surface-800 text-2xs uppercase tracking-wide text-ink-400">
                  <th className="px-4 py-2 font-medium">Type</th>
                  <th className="px-4 py-2 font-medium">Value</th>
                  <th className="px-4 py-2 font-medium">Description</th>
                  <th className="px-4 py-2 font-medium">Added</th>
                  <th className="px-4 py-2 font-medium text-right">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-800">
                {iocs.data.items.map((entry) => (
                  <IocRow key={entry.id} entry={entry} canManage={canManageIocs} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="Watchlist is empty" />
        )}
      </Card>

      <Modal open={adding} title="Add an indicator" onClose={() => setAdding(false)}>
        <div className="space-y-3">
          <div>
            <label htmlFor="ioc-type" className="block text-2xs text-ink-300 mb-1">
              Type
            </label>
            <Select
              id="ioc-type"
              value={iocType}
              onChange={(event) => setIocType(event.target.value as IOCType)}
              className="w-full"
            >
              <option value="ip_address">IP address</option>
              <option value="file_hash">File hash</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
            </Select>
          </div>
          <div>
            <label htmlFor="ioc-value" className="block text-2xs text-ink-300 mb-1">
              Value
            </label>
            <Input
              id="ioc-value"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder={iocType === 'ip_address' ? '203.0.113.66' : ''}
            />
          </div>
          <div>
            <label htmlFor="ioc-description" className="block text-2xs text-ink-300 mb-1">
              Description
            </label>
            <Textarea
              id="ioc-description"
              rows={2}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Where this came from and why it matters"
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button onClick={() => setAdding(false)}>Cancel</Button>
            <Button variant="primary" disabled={!value.trim() || createIoc.isPending} onClick={submitIoc}>
              Add
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

function IocRow({
  entry,
  canManage,
}: {
  entry: { id: string; ioc_type: string; value: string; description: string; active: boolean; created_at: string }
  canManage: boolean
}) {
  const update = useUpdateIoc(entry.id)
  const toast = useToast()
  return (
    <tr className="hover:bg-surface-850">
      <td className="px-4 py-2 text-2xs text-ink-300">{titleCase(entry.ioc_type)}</td>
      <td className="px-4 py-2">
        <Mono className="break-all">{entry.value}</Mono>
      </td>
      <td className="px-4 py-2 text-2xs text-ink-300 max-w-md">{entry.description}</td>
      <td className="px-4 py-2 text-2xs text-ink-400 whitespace-nowrap">
        {formatTimestamp(entry.created_at)}
      </td>
      <td className="px-4 py-2 text-right">
        {canManage ? (
          <Button
            size="sm"
            variant={entry.active ? 'ghost' : 'primary'}
            disabled={update.isPending}
            onClick={async () => {
              await update.mutateAsync({ active: !entry.active })
              toast.push(entry.active ? 'Indicator deactivated.' : 'Indicator reactivated.', 'success')
            }}
          >
            {entry.active ? 'Active' : 'Inactive'}
          </Button>
        ) : (
          <span className="text-2xs text-ink-300">{entry.active ? 'Active' : 'Inactive'}</span>
        )}
      </td>
    </tr>
  )
}
