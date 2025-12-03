import dotenv from 'dotenv';
dotenv.config({ path: '.env.local' });

const NGROK_URL = 'https://unglamourous-unaccustomedly-audra.ngrok-free.dev';
const LOCAL_URL = 'http://localhost:3000';

async function testViaAPI() {
  console.log('🧪 Testing Analysis via API...\n');
  
  // First, we need to get a contact ID
  // Let's try to get it from the API
  console.log('📡 Step 1: Getting a contact ID...\n');
  
  try {
    // Try to get contacts (this requires auth, but let's see what happens)
    const contactsResponse = await fetch(`${LOCAL_URL}/api/contacts?limit=1`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      }
    });
    
    if (contactsResponse.ok) {
      const contactsData = await contactsResponse.json();
      if (contactsData.contacts && contactsData.contacts.length > 0) {
        const contactId = contactsData.contacts[0].id;
        console.log(`✅ Found contact: ${contactId}\n`);
        
        // Now test the debug analysis endpoint
        console.log('📡 Step 2: Testing analysis via debug endpoint...\n');
        
        const debugResponse = await fetch(`${LOCAL_URL}/api/debug-analysis`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ contactId })
        });
        
        if (debugResponse.ok) {
          const debugData = await debugResponse.json();
          console.log('📊 Analysis Test Results:\n');
          console.log(JSON.stringify(debugData, null, 2));
          
          if (debugData.error) {
            console.log('\n❌ Error occurred during analysis:');
            console.log(`   Message: ${debugData.error.message}`);
            console.log(`   Type: ${debugData.error.type}`);
            if (debugData.error.stack) {
              console.log(`   Stack: ${debugData.error.stack.join('\n')}`);
            }
          } else if (debugData.analysis) {
            if (debugData.analysis.usedFallback) {
              console.log('\n⚠️  Analysis used fallback scoring');
              console.log('   This means the AI API call failed.');
            } else {
              console.log('\n✅ Analysis succeeded with AI!');
            }
          }
        } else {
          const errorText = await debugResponse.text();
          console.log(`❌ Debug endpoint failed: ${debugResponse.status}`);
          console.log(`   Response: ${errorText}\n`);
        }
      } else {
        console.log('⚠️  No contacts found\n');
      }
    } else {
      const errorText = await contactsResponse.text();
      console.log(`⚠️  Could not get contacts (might need auth): ${contactsResponse.status}`);
      console.log(`   Response: ${errorText.substring(0, 200)}\n`);
      console.log('💡 You may need to be logged in to test this.\n');
      console.log('   Try accessing the debug endpoint from your browser:');
      console.log(`   ${LOCAL_URL}/api/debug-analysis`);
      console.log('   (Use browser dev tools to make a POST request with a contactId)\n');
    }
  } catch (error) {
    console.error('❌ Error:', error);
    if (error instanceof Error) {
      console.error('   Message:', error.message);
    }
  }
  
  // Also test the direct API
  console.log('📡 Step 3: Testing NVIDIA API directly...\n');
  const apiKey = process.env.NVIDIA_API_KEY;
  
  if (!apiKey) {
    console.log('❌ NVIDIA_API_KEY not found in environment\n');
    return;
  }
  
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
            content: 'Analyze this conversation and return ONLY a JSON object: {"summary": "test", "leadScore": 75, "leadStatus": "CONTACTED"}. Do not include any other text.'
          }
        ],
        max_tokens: 4000,
        temperature: 0.7
      })
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log('✅ Direct NVIDIA API call successful!\n');
      console.log(`   Has content: ${!!data.choices?.[0]?.message?.content}`);
      console.log(`   Has reasoning_content: ${!!data.choices?.[0]?.message?.reasoning_content}`);
      
      const content = data.choices?.[0]?.message?.content || '';
      if (content) {
        console.log(`   Content preview: ${content.substring(0, 200)}...\n`);
        
        // Try to parse JSON
        try {
          const jsonMatch = content.match(/\{[\s\S]*\}/);
          if (jsonMatch) {
            const parsed = JSON.parse(jsonMatch[0]);
            console.log('✅ Successfully parsed JSON:');
            console.log(`   Summary: ${parsed.summary}`);
            console.log(`   Lead Score: ${parsed.leadScore}`);
            console.log(`   Lead Status: ${parsed.leadStatus}\n`);
          }
        } catch (e) {
          console.log('⚠️  Could not parse JSON from response\n');
        }
      }
    } else {
      const errorText = await response.text();
      console.log(`❌ Direct API call failed: ${response.status}`);
      console.log(`   Response: ${errorText.substring(0, 300)}\n`);
    }
  } catch (error) {
    console.error('❌ Direct API call error:', error);
    if (error instanceof Error) {
      console.error('   Message:', error.message);
    }
  }
}

testViaAPI().catch(console.error);




