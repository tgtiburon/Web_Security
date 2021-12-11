//console.log("script.js loaded!");


// Variables
const vTotalInfo = '8cf0ca0342f8870b2601ff6a6292c366162f55ab28d1213baafd6c4f06a2c53a';
const vTotalInfo2 = 'a32c9f576baf76b93b4ea264cd363cd499c8cd45c0a9d6d861671cfea6fe2850';
let savedVTID = []; //Holds the saved ID from Virus Total 
let savedVTResults = []; //Holds the results from the URL scan
let userSearch = "";
let lastWebScan = "";



// Functions

/*  Function: initialLoad() 
    => Called when the website loads to take care of any housekeeping issues.
    args: none
    return: none
*/

const initialLoad = () => {
   
    // load saved data to populate the last scan
    loadSavedData();
  
}//end initialLoad()

/*  Function: loadSavedData()
    => loads all saved data to populate the last scan
    args: none
    return: none
*/

let loadSavedData = function() {
    
    let savedVTID = localStorage.getItem("savedVTID");
    //no savedVTID make one
    if (!savedVTID) {
        savedVTID = [];
    } else {
        // load and parse savedVTID  This is the ID returned
        // by virustotal when we send the url to it.
        // We use the ID by sending it to virustotal, which it uses to analyze the url.
       savedVTID = JSON.parse(localStorage.getItem("savedVTID"));
    
    }

    finalResultsObjArr = localStorage.getItem("finalResultsObjArr");
    //no savedVTResults
    if (!finalResultsObjArr) {
        finalResultsObjArr = [];
    }else {
        // load and parse savedVTResults
       let finalResultsObjArr = JSON.parse(localStorage.getItem("finalResultsObjArr"));
       
    }
 
    lastWebScan = JSON.parse(localStorage.getItem("lastWebScan"));
        if(!lastWebScan) {
            lastWebScan = "none";
        } else {
            let lastWebScan = JSON.parse(localStorage.getItem("lastWebScan"));
        }
    
        savedVTResults = localStorage.getItem("savedVTResults");
        //no savedVTResults
        if (!savedVTResults) {
            savedVTResults = [];
        }else {
            // load and parse savedVTResults -- This is the saved results from virus
            // total after we sent it for analysis.
           let savedVTResults = JSON.parse(localStorage.getItem("savedVTResults"));
            processVTData(savedVTResults);
        }
   
};

/*  Function: webSiteGetID 
    => fetches the special VirusTotal ID needed to run analyse
    args: URL that needs it's unique ID
    return: none
*/

const webSiteGetID  = (userSearch) => {
   

    // website we want to scan.  We will have input box later

    // below is old code before "fixing" the cors
    //let myRequestURL = "https://www.virustotal.com/api/v3/urls";
   // need to submit as a FormData object
   // let formData = new FormData();
  // formData.append('url', userSearch);
  
// build the options object for the fetch command.
    const options = {
        method: 'POST',
        headers: {
            "X-Apikey" : vTotalInfo,
            //Accept: 'application/json',
           ' Access-Control-Allow-Headers': 'Content-Type, Authorization',
            Accept: 'text/plain',
            'Content-Type': 'application/x-www-form-urlencoded'
        },
   
        body: new URLSearchParams({url : userSearch})//,
  
    };

    // fetch using the URL and the options object
    // test
    fetch('https://www.virustotal.com/api/v3/urls', options).then(function(response){ 
       // fetch('https://cors-anywhere.herokuapp.com/https://www.virustotal.com/api/v3/urls', options).then(function(response){ 


        if(response.ok) {
          // it worked so save the id
            response.json().then(function(data) {

                // Virus total sends us the ID of the URL 
                savedVTID = data.data.id;
                // for debugging print the ID we get back from the scan
                //console.log("ID= " + savedVTID);
                  
                localStorage.setItem("savedVTID", JSON.stringify(savedVTID));
                // Now we send the special ID virus total sent us, back to them to analyze
                // I am not sure why they don't do it all in one step.  
                webSiteScan(savedVTID);
            
            });
        } else {
            //it failed
            console.log("WebsiteGetID failed to get an ID!");
        }
    });

};//End websiteGetID()


/*  Function: webSiteScan
    => Takes the VT url ID and sends it to get analyzed
    and saves the result to localStorage to cut down on API calls.
    args: savedVTID
    return: none
*/
const webSiteScan = (savedVTID) => {
    // URL for requesting a scan of the URL with the special ID
    let myRequestURL = "https://www.virustotal.com/api/v3/analyses/" + savedVTID;
    // set up the header
    let myHeaders = new Headers();
    myHeaders = {"X-Apikey" : vTotalInfo };
    // create myRequestObject
    myRequestObject = {
        method: 'GET',
        headers: myHeaders,
        mode: 'cors'    
    }

    // try and fetch the analysis of the url
   fetch(myRequestURL, myRequestObject).then(function(response){ 
 
        if(response.ok) {
            // it worked parse and store the data
        
            response.json().then(function(data) {

                // Lets see if it actually returned results
                
           
                savedVTResults = data;

                // Need to wait for analysis;
                //for debugging print the status of the search
               // console.log("Status= "+ savedVTResults.data.attributes.status)
                let isDone =  savedVTResults.data.attributes.status;
                if(isDone === "queued") {
                   
                    //for debugging let log that we are waiting for a response
                   // console.log("need to wait")
                    setTimeout(() => {webSiteScan(savedVTID)}, 7000);
                
                    $("#card_holder").text("Waiting on analysis...")
                        .css("color", "#1D435C")
                        .css("font-size", "40px")
                        .css("background-color", "#EFBF1F");
                    return;
                }
               
                localStorage.setItem("savedVTResults", JSON.stringify(savedVTResults));
                localStorage.setItem("lastWebScan",JSON.stringify(userSearch) );
                // Time to process all that data
                processVTData(savedVTResults);     
            });

        } else {
            // it failed.
            console.log("It failed!");
           
        }  
    });  
}// end webSiteScan




/*  Function: processVTData
    => Takes the data from the analyze call at VT 
    and puts it into easy to use objects or array
    args: savedVTResults
    return: none
*/

processVTData = (savedVTResults) => {
    

    // storing the savedVTResults sent to the function into a variable with 
    // the same name
    savedVTResults = savedVTResults;
    // We are turning the results into a temporary object so we can 
    // use forEach to loop through it later.
    let tmpObj = savedVTResults.data.attributes.results
    // iterator for the Object loop
   
    let finalResultsObjArr = [];
    let dirtyResults = [];
    let totalClean = 0; // keep track of the results
    let totalDirty = 0;

    // Using forEach to go through the object array so we can store the results in an easier format
    Object.values(tmpObj).forEach(val=> {

        // push the data into finalResultsObjArr for displaying results.
        finalResultsObjArr.push({engine:val.engine_name, verdict:val.result});

        // Lets analyze the data 
        if(val.result === "clean" || val.result === "unrated") {
            totalClean++
        } else {
            totalDirty++
            //build a dirtyResults object to store so we can build UI easier
            dirtyResults.push({engine:val.engine_name, verdict:val.result});
        }
    });
 
    // empty the scan summary div so we can rebuilt it
    $("#scan_summary").empty();

    //SCAN SUMMARY LEFT COLUMN


    let resultsStats =  savedVTResults.data.attributes.stats;
  
    // Build the UL for summary
    summaryUlEl = $("<ul>")
     .addClass("column  ml-2 mt-4")
     .text("Last Scan Summary");

    $("#scan_summary").append(summaryUlEl);
    // if user has not searched anything, use lastwebScan
        if(userSearch === "") {
    
            userSearch = lastWebScan;
        }

        summaryIlEl = $("<li>").text("Site: " + userSearch)
            .addClass("siteLI");
        summaryUlEl.append(summaryIlEl);
        summaryIlEl = $("<li>").text("Harmless: " + resultsStats.harmless);
        summaryUlEl.append(summaryIlEl);
        summaryIlEl = $("<li>").text("Malicous: " + resultsStats.malicious);
        summaryUlEl.append(summaryIlEl);
        summaryIlEl = $("<li>").text("Suspicious: " + resultsStats.suspicious);
        summaryUlEl.append(summaryIlEl);
        summaryIlEl = $("<li>").text("Undetected: " + resultsStats.undetected);
        summaryUlEl.append(summaryIlEl);

        // clean the card_holder div
        $("#card_holder").empty();
        $("#card_holder").css("background-color", "var(--pal2)")
            .css("font-size", "1em");
        Object.values(dirtyResults).forEach(val=> {
       
      cardDivEl = $("<div>")
      .addClass("card p-0 m-3")
      .css("background-color","#EFBF1F");
   
      if(val.verdict === "malicious") {
        cardDivEl = $("<div>")
        .addClass("card p-0 m-3")
        .css("background-color", "var(--pal4)")
        
      }

        $("#card_holder").append(cardDivEl);

        cardContentEl = $("<div>")
        .addClass("card-content is-1 p-2 m-0 is-half-mobile");
        // .text(val.engine + ": \n  "+ val.verdict)
        $(cardDivEl).append(cardContentEl);

        //build a card for each one
        cardTitleEl = $("<div>")
            .addClass("content-title has-text-weight-bold is-4 p-0 m-0")
        // .text(val.engine + ": \n  "+ val.verdict)
            .text(val.engine + ": ");
        $(cardContentEl).append(cardTitleEl);

        cardSubTitleEl = $("<div>")
            .addClass("subtitle has-text-weight-bold is-6 m-0 p-0")
            .text(val.verdict);
        $(cardContentEl).append(cardSubTitleEl);

    });

    // No bad results lets display a message saying
    // that the website is safe to use if no bad results found
    if(totalDirty === 0) {
        $("#card_holder").text("Website is safe to use.")
            .css("color", "#5FED6E")
            .css("font-size", "50px")
            .css("text-shadow", "1px 1px 2px black")
            .css("font-weight", "bolder");
    }

    // lets save the new object array.
    // saved as   Engine Name :  Result   
    localStorage.setItem("finalResultsObjArr", JSON.stringify(finalResultsObjArr));
}; //end processVTData



// user hits the search button

$("body").on("click", "#srchBtn", function() {
    // set userSearch equal to the user input
    userSearch = $("input").val();
  
    // clear search
    $("input").val("");
    webSiteGetID(userSearch);
});

// Let the user hit enter for the website input

$("input").keypress(function(e) {
    if (event.which === 13) {
       
        $("#srchBtn").trigger("click");
        return false;
    }
});



/*  Function: getNews()
    => gets the 5 latest new york times tech articles 
    args: none
    return: none
*/
  
  let articleList = []

async function getNews() {
    const endpoint = "https://api.nytimes.com/svc/news/v3/content/all/technology.json?api-key=gx3ZiB0uV9hM9QFpzZp2tyXKZs8pnpj0";

    const options = {
        method: "GET",
        headers: {
            "Accept": "application/json"
        }
    }

    const request = await fetch(endpoint, options)
    .then(function(response) {
        if(response) {
            response.json().then(function(data){
                displayArticles(data);
               
            })
        }
    })
    
};

/*  Function: displayArticles()
    => displays the NY Times articles
    args: data from getNews
    return: none
*/

function displayArticles(data) {
    // get the first 5 articles
    for(let i = 0; i < 5; i++) {
        articleList.push(data.results[i]);
    }

    // go through the articles and grab the url/article names to display on webpage
    for(let i = 0; i < articleList.length; i++) {

        let box = document.createElement("div");
        box.classList.add("box", "mx-4");
        
        let article = document.createElement("article");
        article.classList.add("media");

        let mediaLeft = document.createElement("div");
        mediaLeft.classList.add("media-left");

        let mediaFigure = document.createElement("figure");
        mediaFigure.classList.add("image", "is-96x96");

        // Sometimes there is no image  
        let img = document.createElement("img");
      
        if(articleList[i].thumbnail_standard === undefined) {
            
            img.src = "./assets/images/poweredby_nytimes_30a.png";

        } else {
          
            img.src = articleList[i].thumbnail_standard;
        };
        
       

        let mediaContent = document.createElement("div");
        mediaContent.classList.add("media-content");

        let content = document.createElement("div");
        content.classList.add("media-content");

        let articleLink = document.createElement("a");
        articleLink.textContent = articleList[i].title;
        articleLink.href = articleList[i].url;
        articleLink.classList.add("has-text-weight-bold");
        articleLink.target = "_blank";

        document.querySelector("#Tech_Stories").appendChild(box);
        box.appendChild(article);
        article.appendChild(mediaLeft);
        mediaLeft.appendChild(mediaFigure);
        mediaFigure.appendChild(img);
        article.appendChild(mediaContent);
        mediaContent.appendChild(content);
        content.appendChild(articleLink);

    }
    let nyTimesImg = document.createElement("img");
    nyTimesImg.src = "./assets/images/poweredby_nytimes_150a.png"
    nyTimesImg.classList.add("logoImg");
    document.querySelector("#Tech_Stories").appendChild(nyTimesImg)

};





// Function calls
initialLoad();// Call this to start the website.

// load news after page load


getNews(); //get NY Times news