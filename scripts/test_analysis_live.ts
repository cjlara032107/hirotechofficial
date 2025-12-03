import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

import { prisma, connectPrisma } from '@/lib/db';
import { analyzeWithFallback } from '@/lib/ai/enhanced-analysis';

async function testAnalysisLive() {
  try {
    console.log('🧪 Testing Live Analysis...\n');
    
    await connectPrisma();
    console.log('✅ Database connected\n');
    
    // Find a contact with the "Analysis failed" message
    const contact = await prisma.contact.findFirst({
      where: {
        aiContext: {
          contains: 'Analysis failed but assigned score'
        }
      },
      include: {
        page: {
          include: {
            autoPipeline: {
              include: {
                stages: {
                  orderBy: { order: 'asc' }
                }
              }
            }
          }
        },
        messages: {
          orderBy: { createdAt: 'asc' },
          take: 50
        }
      }
    });
    
    if (!contact) {
      console.log('⚠️  No contact found with "Analysis failed" message');
      console.log('   Looking for any contact with messages...\n');
      
      const anyContact = await prisma.contact.findFirst({
        where: {
          messages: {
            some: {}
          }
        },
        include: {
          page: {
            include: {
              autoPipeline: {
                include: {
                  stages: {
                    orderBy: { order: 'asc' }
                  }
                }
              }
            }
          },
          messages: {
            orderBy: { createdAt: 'asc' },
            take: 50
          }
        }
      });
      
      if (!anyContact) {
        console.log('❌ No contacts with messages found');
        return;
      }
      
      console.log(`✅ Found contact: ${anyContact.id}`);
      console.log(`   Messages: ${anyContact.messages.length}`);
      console.log(`   Has pipeline: ${!!anyContact.page?.autoPipeline}`);
      console.log(`   Pipeline stages: ${anyContact.page?.autoPipeline?.stages.length || 0}\n`);
      
      await testContactAnalysis(anyContact);
      return;
    }
    
    console.log(`✅ Found failing contact: ${contact.id}`);
    console.log(`   Messages: ${contact.messages.length}`);
    console.log(`   Has pipeline: ${!!contact.page?.autoPipeline}`);
    console.log(`   Pipeline stages: ${contact.page?.autoPipeline?.stages.length || 0}\n`);
    
    await testContactAnalysis(contact);
    
  } catch (error) {
    console.error('❌ Test error:', error);
    if (error instanceof Error) {
      console.error('   Message:', error.message);
      console.error('   Stack:', error.stack?.split('\n').slice(0, 10).join('\n'));
    }
  } finally {
    await prisma.$disconnect();
  }
}

async function testContactAnalysis(contact: any) {
  const messagesToAnalyze = contact.messages.map((msg: any) => ({
    id: msg.id,
    text: msg.text || '',
    from: msg.from || 'unknown',
    timestamp: msg.createdAt,
    type: msg.type || 'text'
  }));
  
  console.log('📝 Preparing Analysis...\n');
  console.log(`   Messages to analyze: ${messagesToAnalyze.length}`);
  if (messagesToAnalyze.length > 0) {
    console.log(`   Sample message: "${messagesToAnalyze[0]?.text?.substring(0, 50) || 'N/A'}..."\n`);
  }
  
  // Check environment
  console.log('🔑 Environment Check:');
  const apiKey = process.env.NVIDIA_API_KEY;
  console.log(`   NVIDIA_API_KEY: ${apiKey ? `${apiKey.substring(0, 20)}... (${apiKey.length} chars)` : '❌ MISSING'}`);
  console.log(`   DATABASE_URL: ${process.env.DATABASE_URL ? '✅ Set' : '❌ MISSING'}\n`);
  
  if (!apiKey) {
    console.error('❌ NVIDIA_API_KEY not found. Cannot test.');
    return;
  }
  
  // Test analysis
  console.log('🧪 Testing analyzeWithFallback...\n');
  
  try {
    let result;
    
    if (contact.page?.autoPipeline?.stages) {
      console.log(`   Using pipeline analysis with ${contact.page.autoPipeline.stages.length} stages`);
      console.log(`   Stages: ${contact.page.autoPipeline.stages.map((s: any) => s.name).join(', ')}\n`);
      
      result = await analyzeWithFallback(
        messagesToAnalyze,
        contact.page.autoPipeline.stages,
        contact.lastInteraction || undefined,
        3
      );
    } else {
      console.log(`   Using simple analysis (no pipeline)\n`);
      
      result = await analyzeWithFallback(
        messagesToAnalyze,
        undefined,
        contact.lastInteraction || undefined,
        3
      );
    }
    
    console.log('📊 Analysis Result:\n');
    console.log(`   Success: ${!!result?.analysis ? '✅' : '❌'}`);
    console.log(`   Used Fallback: ${result?.usedFallback ? '⚠️  YES' : '✅ NO'}`);
    console.log(`   Retry Count: ${result?.retryCount || 0}`);
    
    if (result?.analysis) {
      console.log(`\n   Summary: ${result.analysis.summary?.substring(0, 150)}...`);
      console.log(`   Lead Score: ${result.analysis.leadScore}`);
      console.log(`   Lead Status: ${result.analysis.leadStatus}`);
      console.log(`   Recommended Stage: ${result.analysis.recommendedStage || 'N/A'}`);
      console.log(`   Confidence: ${result.analysis.confidence || 'N/A'}\n`);
      
      if (result.usedFallback) {
        console.log('⚠️  WARNING: Analysis used fallback scoring instead of AI');
        console.log('   This means the AI API call failed or returned invalid data.\n');
        console.log('   Possible causes:');
        console.log('   1. API key is invalid or expired');
        console.log('   2. API rate limit exceeded');
        console.log('   3. Network timeout');
        console.log('   4. API returned unexpected format\n');
      } else {
        console.log('✅ SUCCESS: AI analysis completed successfully!\n');
      }
    } else {
      console.log('❌ Analysis returned null result\n');
    }
    
  } catch (error) {
    console.error('❌ Analysis threw error:');
    console.error('   Error:', error);
    if (error instanceof Error) {
      console.error('   Message:', error.message);
      console.error('   Type:', error.constructor.name);
      console.error('   Stack:', error.stack?.split('\n').slice(0, 10).join('\n'));
    }
    console.log('');
  }
  
  // Test direct API call
  console.log('🧪 Testing Direct NVIDIA API Call...\n');
  try {
    const response = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'openai/gpt-oss-120b',
        messages: [
          {
            role: 'user',
            content: 'Say "test" and nothing else.'
          }
        ],
        max_tokens: 10,
        temperature: 0.7
      })
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.log(`❌ Direct API call failed: ${response.status}`);
      console.log(`   Response: ${errorText.substring(0, 300)}\n`);
    } else {
      const data = await response.json();
      console.log('✅ Direct API call successful!');
      console.log(`   Response has content: ${!!data.choices?.[0]?.message?.content}`);
      console.log(`   Response has reasoning_content: ${!!data.choices?.[0]?.message?.reasoning_content}\n`);
    }
  } catch (error) {
    console.log('❌ Direct API call error:');
    console.error('   Error:', error);
    if (error instanceof Error) {
      console.error('   Message:', error.message);
    }
    console.log('');
  }
}

testAnalysisLive().catch(console.error);




