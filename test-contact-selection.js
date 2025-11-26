/**
 * Test script to simulate contact selection behavior
 * This tests that only selected contacts are sent to the API, not all contacts
 */

// Simulate the selection state
let selectedIds = new Set();
let selectAllPages = false;
let totalContactsCount = 0;
let allContactIds = [];

// Mock contacts data
const mockContacts = [
  { id: 'contact1', firstName: 'John', lastName: 'Doe' },
  { id: 'contact2', firstName: 'Jane', lastName: 'Smith' },
  { id: 'contact3', firstName: 'Bob', lastName: 'Johnson' },
  { id: 'contact4', firstName: 'Alice', lastName: 'Williams' },
  { id: 'contact5', firstName: 'Charlie', firstName: 'Brown' },
];

// Simulate selecting all pages
function simulateSelectAllPages() {
  console.log('\n=== Simulating "Select All Pages" ===');
  allContactIds = mockContacts.map(c => c.id);
  totalContactsCount = allContactIds.length;
  selectedIds = new Set(allContactIds);
  selectAllPages = true;
  console.log(`Selected ${selectedIds.size} contacts (all pages)`);
  console.log('selectedIds:', Array.from(selectedIds));
  console.log('selectAllPages:', selectAllPages);
}

// Simulate selecting just one contact
function simulateSelectOne(contactId) {
  console.log(`\n=== Simulating "Select One Contact: ${contactId}" ===`);
  
  // Clear previous selection
  selectedIds = new Set([contactId]);
  selectAllPages = false;
  allContactIds = [];
  totalContactsCount = 0;
  
  console.log(`Selected 1 contact: ${contactId}`);
  console.log('selectedIds:', Array.from(selectedIds));
  console.log('selectAllPages:', selectAllPages);
}

// Simulate the handleBulkAction function (the critical part)
function simulateBulkAction(action) {
  console.log(`\n=== Simulating Bulk Action: ${action} ===`);
  
  // Get current selection (using ref pattern)
  const currentSelectedIds = selectedIds;
  const contactIdsToSend = Array.from(currentSelectedIds);
  
  if (contactIdsToSend.length === 0) {
    console.log('❌ ERROR: No contacts selected!');
    return null;
  }
  
  // Safety check
  if (selectAllPages && contactIdsToSend.length !== totalContactsCount) {
    console.log('⚠️  WARNING: selectAllPages was true but selection changed!');
    console.log(`   Expected: ${totalContactsCount}, Got: ${contactIdsToSend.length}`);
    selectAllPages = false;
    allContactIds = [];
    totalContactsCount = 0;
  }
  
  console.log(`✅ Sending ${contactIdsToSend.length} contact(s) to API`);
  console.log('Contact IDs:', contactIdsToSend);
  console.log('selectAllPages flag:', selectAllPages);
  
  return {
    action,
    contactIds: contactIdsToSend,
    count: contactIdsToSend.length
  };
}

// Test scenarios
console.log('🧪 Testing Contact Selection Logic\n');
console.log('Total contacts available:', mockContacts.length);

// Test 1: Select all pages, then analyze
console.log('\n📋 TEST 1: Select All Pages → Analyze');
simulateSelectAllPages();
const result1 = simulateBulkAction('analyze');
console.log('Result:', result1);
console.log('Expected: 5 contacts');
console.log(result1?.count === 5 ? '✅ PASS' : '❌ FAIL');

// Test 2: Select all pages, then select just one, then analyze
console.log('\n📋 TEST 2: Select All Pages → Select One → Analyze');
simulateSelectAllPages();
simulateSelectOne('contact1');
const result2 = simulateBulkAction('analyze');
console.log('Result:', result2);
console.log('Expected: 1 contact');
console.log(result2?.count === 1 ? '✅ PASS' : '❌ FAIL');

// Test 3: Select one directly, then analyze
console.log('\n📋 TEST 3: Select One Directly → Analyze');
simulateSelectOne('contact2');
const result3 = simulateBulkAction('analyze');
console.log('Result:', result3);
console.log('Expected: 1 contact');
console.log(result3?.count === 1 ? '✅ PASS' : '❌ FAIL');

// Test 4: Select multiple manually
console.log('\n📋 TEST 4: Select Multiple Manually → Analyze');
selectedIds = new Set(['contact1', 'contact3', 'contact5']);
selectAllPages = false;
allContactIds = [];
totalContactsCount = 0;
const result4 = simulateBulkAction('analyze');
console.log('Result:', result4);
console.log('Expected: 3 contacts');
console.log(result4?.count === 3 ? '✅ PASS' : '❌ FAIL');

// Test 5: Edge case - select all pages, then manually deselect one
console.log('\n📋 TEST 5: Select All Pages → Deselect One → Analyze');
simulateSelectAllPages();
// Manually deselect one
selectedIds.delete('contact1');
selectAllPages = false; // Should be reset
allContactIds = [];
totalContactsCount = 0;
const result5 = simulateBulkAction('analyze');
console.log('Result:', result5);
console.log('Expected: 4 contacts (5 - 1)');
console.log(result5?.count === 4 ? '✅ PASS' : '❌ FAIL');

console.log('\n✅ All tests completed!');

