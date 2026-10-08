import { formatTimestamp } from "@/lib/timestamp";

/** An API timestamp in the viewer's local time with its offset; the UTC ISO value on hover. */
export function Timestamp({ value }: { value: unknown }) {
  const { text, iso } = formatTimestamp(value);
  if (iso === null) return <>{text}</>;
  return (
    <time dateTime={iso} title={iso}>
      {text}
    </time>
  );
}
