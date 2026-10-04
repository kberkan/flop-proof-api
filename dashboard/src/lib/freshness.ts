// Freshness label for figures that reload in the background (overview page).
// "Live" only while the most recent load succeeded; never for data that has
// not loaded yet or that a failed reload left on screen.

export type LoadOutcome = "pending" | "ok" | "failed";

export type Freshness = {
  live: boolean;
  label: string;
};

export function freshness(outcome: LoadOutcome): Freshness {
  switch (outcome) {
    case "ok":
      return { live: true, label: "Live" };
    case "failed":
      return { live: false, label: "Not updated" };
    case "pending":
      return { live: false, label: "Loading…" };
    default:
      return { live: false, label: "Not updated" };
  }
}
