/**
 * Script to check for common API route errors
 * Usage: npx tsx scripts/check-api-errors.ts
 */
import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';

interface ErrorPattern {
  pattern: RegExp;
  name: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
}

const errorPatterns: ErrorPattern[] = [
  {
    pattern: /session\.user\.organizationId[^?]/,
    name: 'Missing null check for organizationId',
    severity: 'high',
    description: 'organizationId accessed without optional chaining or null check',
  },
  {
    pattern: /session\.user\.id[^?]/,
    name: 'Missing null check for user.id',
    severity: 'high',
    description: 'user.id accessed without optional chaining or null check',
  },
  {
    pattern: /await.*\.json\(\)/,
    name: 'Unsafe JSON parsing',
    severity: 'medium',
    description: 'JSON parsing without content-type check',
  },
  {
    pattern: /prisma\.[a-zA-Z]+\.(findMany|findUnique|create|update|delete)/,
    name: 'Prisma operation without try-catch',
    severity: 'medium',
    description: 'Prisma operations should be wrapped in try-catch',
  },
  {
    pattern: /\.map\(|\.filter\(|\.forEach\(/,
    name: 'Array operations on potentially undefined',
    severity: 'low',
    description: 'Array operations should check if array exists first',
  },
];

function findApiRoutes(dir: string): string[] {
  const routes: string[] = [];
  
  function walk(currentDir: string) {
    const entries = readdirSync(currentDir);
    
    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const stat = statSync(fullPath);
      
      if (stat.isDirectory()) {
        walk(fullPath);
      } else if (entry === 'route.ts' || entry === 'route.js') {
        routes.push(fullPath);
      }
    }
  }
  
  walk(dir);
  return routes;
}

function checkFile(filePath: string): Array<{ pattern: ErrorPattern; line: number; content: string }> {
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const issues: Array<{ pattern: ErrorPattern; line: number; content: string }> = [];
  
  for (const pattern of errorPatterns) {
    lines.forEach((line, index) => {
      if (pattern.pattern.test(line)) {
        // Skip if it's in a comment or already has null check
        if (!line.trim().startsWith('//') && !line.includes('?.') && !line.includes('if (')) {
          issues.push({
            pattern,
            line: index + 1,
            content: line.trim(),
          });
        }
      }
    });
  }
  
  return issues;
}

function main() {
  console.log('🔍 Checking API routes for common errors...\n');
  
  const apiDir = join(process.cwd(), 'src', 'app', 'api');
  const routes = findApiRoutes(apiDir);
  
  console.log(`Found ${routes.length} API route files\n`);
  
  const allIssues: Array<{ file: string; issues: Array<{ pattern: ErrorPattern; line: number; content: string }> }> = [];
  
  for (const route of routes) {
    const issues = checkFile(route);
    if (issues.length > 0) {
      allIssues.push({
        file: route.replace(process.cwd(), ''),
        issues,
      });
    }
  }
  
  if (allIssues.length === 0) {
    console.log('✅ No issues found!\n');
    return;
  }
  
  // Group by severity
  const highSeverity: typeof allIssues = [];
  const mediumSeverity: typeof allIssues = [];
  const lowSeverity: typeof allIssues = [];
  
  for (const fileIssue of allIssues) {
    const hasHigh = fileIssue.issues.some(i => i.pattern.severity === 'high');
    const hasMedium = fileIssue.issues.some(i => i.pattern.severity === 'medium');
    
    if (hasHigh) {
      highSeverity.push(fileIssue);
    } else if (hasMedium) {
      mediumSeverity.push(fileIssue);
    } else {
      lowSeverity.push(fileIssue);
    }
  }
  
  // Print high severity issues
  if (highSeverity.length > 0) {
    console.log('🔴 HIGH SEVERITY ISSUES:\n');
    for (const fileIssue of highSeverity) {
      console.log(`📄 ${fileIssue.file}`);
      for (const issue of fileIssue.issues.filter(i => i.pattern.severity === 'high')) {
        console.log(`   Line ${issue.line}: ${issue.pattern.name}`);
        console.log(`   ${issue.content.substring(0, 80)}...`);
        console.log(`   ${issue.pattern.description}\n`);
      }
    }
  }
  
  // Print medium severity issues
  if (mediumSeverity.length > 0) {
    console.log('🟡 MEDIUM SEVERITY ISSUES:\n');
    for (const fileIssue of mediumSeverity) {
      console.log(`📄 ${fileIssue.file}`);
      for (const issue of fileIssue.issues.filter(i => i.pattern.severity === 'medium')) {
        console.log(`   Line ${issue.line}: ${issue.pattern.name}`);
        console.log(`   ${issue.content.substring(0, 80)}...\n`);
      }
    }
  }
  
  // Summary
  console.log('\n📊 Summary:');
  console.log(`   High: ${highSeverity.length} files`);
  console.log(`   Medium: ${mediumSeverity.length} files`);
  console.log(`   Low: ${lowSeverity.length} files`);
  console.log(`   Total: ${allIssues.length} files with issues\n`);
}

main();









