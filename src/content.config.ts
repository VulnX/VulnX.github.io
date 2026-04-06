import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const posts = defineCollection({
  loader: glob({ pattern: "**/[^_]*.md", base: "./src/content/posts" }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    event: z.string(),
    category: z.string(),
    difficulty: z.string(),
    author: z.array(z.string()),
    tags: z.array(z.string()),
    description: z.string(),
  }),
});

export const collections = { posts };
