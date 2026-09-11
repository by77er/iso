export default function ModelSelect({
  label,
  value,
  models,
  onChange,
  disabled = false,
}: {
  label: string;
  value: string;
  models: string[];
  onChange: (model: string) => void;
  disabled?: boolean;
}) {
  return (
    <label className="model-select">
      <span>{label}</span>
      <select
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        disabled={disabled}
      >
        {!value && <option value="">Master default</option>}
        {[...new Set([...models, ...(value ? [value] : [])])].map((model) => (
          <option key={model} value={model}>
            {model}
          </option>
        ))}
      </select>
    </label>
  );
}
